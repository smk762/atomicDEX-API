use crate::{TrezorError, TrezorPinMatrix3x3Response, TrezorResponse, TrezorResult, TrezorUserInteraction};
use common::log::warn;
use common::mm_error::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures::stream::{self, Stream, StreamExt};
use futures::SinkExt;
use std::pin::Pin;
use std::task::{Context, Poll};

const CHANNEL_BUF_SIZE: usize = 1024;

type EventStream<T> = dyn Stream<Item = TrezorEvent<T>> + Unpin + Send;
pub type PinMatrixResponseTx = oneshot::Sender<TrezorPinMatrix3x3Response>;
type ShutdownTx = oneshot::Sender<()>;
type ShutdownRx = oneshot::Receiver<()>;
pub(crate) type TrezorResponseSender<T> = mpsc::Sender<TrezorEvent<T>>;

pub(crate) fn trezor_response_channel<T>() -> (
    TrezorResponseSender<TrezorResult<T>>,
    TrezorResponseReceiver<TrezorResult<T>>,
    ShutdownRx,
)
where
    T: Send + 'static,
{
    let (response_tx, response_rx) = mpsc::channel(CHANNEL_BUF_SIZE);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let response_rx = TrezorResponseReceiver::new(response_rx, shutdown_tx);
    (response_tx, response_rx, shutdown_rx)
}

pub(crate) async fn response_loop<T>(
    mut response_tx: TrezorResponseSender<TrezorResult<T>>,
    mut result: TrezorResult<TrezorResponse<T>>,
) where
    T: 'static,
{
    loop {
        let response = match result {
            Ok(response) => response,
            Err(e) => {
                // ignore if the receiver is closed
                response_tx.send(TrezorEvent::Ready(Err(e))).await.ok();
                return;
            },
        };
        result = match response {
            TrezorResponse::Ok(t) => {
                response_tx.send(TrezorEvent::Ready(Ok(t))).await.ok();
                return;
            },
            TrezorResponse::ButtonRequest(button_request) => {
                if response_tx.send(TrezorEvent::ButtonRequest).await.is_err() {
                    warn!("Receiver is dropped. Cancel Trezor button-request");
                    button_request.cancel().await;
                    return;
                }
                button_request.ack().await
            },
            TrezorResponse::PinMatrixRequest(pin_request) => {
                let (pin_response_tx, pin_response_rx) = oneshot::channel();
                if response_tx
                    .send(TrezorEvent::PinMatrix3x3Request { pin_response_tx })
                    .await
                    .is_err()
                {
                    warn!("Receiver is dropped. Cancel Trezor pin-matrix-request");
                    pin_request.cancel().await;
                    return;
                }
                let pin_response = match pin_response_rx.await {
                    Ok(pin_response) => pin_response,
                    Err(_) => {
                        warn!("Receiver is dropped. Cancel Trezor pin-matrix-request");
                        pin_request.cancel().await;
                        return;
                    },
                };
                pin_request.ack_pin(pin_response.pin).await
            },
        };
    }
}

pub struct TrezorResponseReceiver<T> {
    stream: Box<EventStream<T>>,
    /// Is used to determine when the receiver is dropped.
    #[allow(dead_code)]
    shutdown_tx: ShutdownTx,
}

impl<T> Stream for TrezorResponseReceiver<T> {
    type Item = TrezorEvent<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Stream::poll_next(Pin::new(&mut self.stream), cx)
    }
}

impl<T> TrezorResponseReceiver<T>
where
    T: Send + 'static,
{
    fn new(stream: mpsc::Receiver<TrezorEvent<T>>, shutdown_tx: ShutdownTx) -> Self {
        TrezorResponseReceiver {
            stream: Box::new(stream),
            shutdown_tx,
        }
    }

    pub fn ready(value: T) -> TrezorResponseReceiver<T> {
        let ready_fut = Box::pin(async move { TrezorEvent::Ready(value) });
        let stream = Box::new(stream::once(ready_fut));
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        TrezorResponseReceiver { stream, shutdown_tx }
    }

    /// Maps [`T`] into [`U`] by applying a function to a contained [`TrezorEvent::Ready`] value.
    /// TODO refactor it to making `F` the `FnOnce` closure.
    pub fn then<F, U>(self, mut f: F) -> TrezorResponseReceiver<U>
    where
        F: FnMut(T) -> U + Send + 'static,
    {
        let stream = Box::new(self.stream.map(move |event| match event {
            TrezorEvent::Ready(t) => TrezorEvent::Ready(f(t)),
            TrezorEvent::ButtonRequest => TrezorEvent::ButtonRequest,
            TrezorEvent::PinMatrix3x3Request { pin_response_tx } => {
                TrezorEvent::PinMatrix3x3Request { pin_response_tx }
            },
        }));

        TrezorResponseReceiver {
            stream,
            shutdown_tx: self.shutdown_tx,
        }
    }

    pub async fn ack_all(mut self) -> TrezorResult<T> {
        while let Some(event) = self.next().await {
            match event {
                TrezorEvent::Ready(ready) => return Ok(ready),
                // Continue getting events.
                TrezorEvent::ButtonRequest => (),
                TrezorEvent::PinMatrix3x3Request { .. } => {
                    return MmError::err(TrezorError::UnexpectedInteractionRequest(
                        TrezorUserInteraction::PinMatrix3x3,
                    ))
                },
            }
        }
        MmError::err(TrezorError::Internal("Event loop finished unexpectedly".to_owned()))
    }
}

impl<T, E1> TrezorResponseReceiver<Result<T, MmError<E1>>>
where
    E1: NotMmError,
{
    /// Maps [`Result<T, MmError<E1>>`] into [`Result<U, MmError<E2>>`] by applying a function to a
    /// contained [`TrezorEvent::Ready`] value.
    /// TODO refactor it to making `F` the `FnOnce` closure.
    pub fn and_then<F, U, E2>(self, mut f: F) -> TrezorResponseReceiver<Result<U, MmError<E2>>>
    where
        T: 'static,
        F: FnMut(T) -> Result<U, MmError<E2>> + Send + 'static,
        E2: From<E1> + NotMmError,
        E1: 'static,
    {
        let stream = Box::new(self.stream.map(move |event| match event {
            TrezorEvent::Ready(Ok(t)) => TrezorEvent::Ready(f(t)),
            TrezorEvent::Ready(Err(e1)) => {
                let (e1, trace) = e1.split();
                let e2 = MmError::err_with_trace(E2::from(e1), trace);
                TrezorEvent::Ready(e2)
            },
            TrezorEvent::ButtonRequest => TrezorEvent::ButtonRequest,
            TrezorEvent::PinMatrix3x3Request { pin_response_tx } => {
                TrezorEvent::PinMatrix3x3Request { pin_response_tx }
            },
        }));

        TrezorResponseReceiver {
            stream,
            shutdown_tx: self.shutdown_tx,
        }
    }
}

pub enum TrezorEvent<T> {
    Ready(T),
    ButtonRequest,
    PinMatrix3x3Request { pin_response_tx: PinMatrixResponseTx },
}
