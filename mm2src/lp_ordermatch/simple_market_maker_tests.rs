use crate::mm2::lp_ordermatch::lp_bot::Provider;
use crate::mm2::lp_ordermatch::lp_bot::TradingBotContext;
use common::block_on;
use common::mm_ctx::MmCtxBuilder;
use common::privkey::key_pair_from_seed;

mod tests {
    use super::*;
    use crate::mm2::lp_ordermatch::lp_bot::TickerInfos;
    use common::mm_number::MmNumber;

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_get_cex_rates() {
        let ctx = MmCtxBuilder::default()
            .with_secp256k1_key_pair(
                key_pair_from_seed("also shoot benefit prefer juice shell elder veteran woman mimic image kidney")
                    .unwrap(),
            )
            .into_mm_arc();
        let trading_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
        let mut registry = block_on(trading_bot_ctx.price_tickers_registry.lock());
        let rates = registry.get_cex_rates("KMD".to_string(), "LTC".to_string());
        assert_eq!(rates.base_provider, Provider::Unknown);
        assert_eq!(rates.rel_provider, Provider::Unknown);

        registry.0.insert("KMD".to_string(), TickerInfos {
            ticker: "KMD".to_string(),
            last_price: MmNumber::from("10"),
            last_updated: "".to_string(),
            last_updated_timestamp: 0,
            volume24_h: "25000".to_string(),
            price_provider: Provider::Binance,
            volume_provider: Provider::Coinpaprika,
            sparkline_7_d: None,
            sparkline_provider: Default::default(),
            change_24_h: "".to_string(),
            change_24_h_provider: Default::default(),
        });

        registry.0.insert("LTC".to_string(), TickerInfos {
            ticker: "LTC".to_string(),
            last_price: MmNumber::from("500.0"),
            last_updated: "".to_string(),
            last_updated_timestamp: 0,
            volume24_h: "25000".to_string(),
            price_provider: Provider::Coingecko,
            volume_provider: Provider::Binance,
            sparkline_7_d: None,
            sparkline_provider: Default::default(),
            change_24_h: "".to_string(),
            change_24_h_provider: Default::default(),
        });

        let rates = registry.get_cex_rates("KMD".to_string(), "LTC".to_string());
        assert_eq!(rates.base_provider, Provider::Binance);
        assert_eq!(rates.rel_provider, Provider::Coingecko);
        assert_eq!(rates.price, MmNumber::from("0.02"));
    }
}
