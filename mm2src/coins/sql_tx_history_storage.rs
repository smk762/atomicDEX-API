use crate::{RemoveTxResult, TransactionDetails, TransactionType, TxHistoryStorage};
use async_trait::async_trait;
use common::async_blocking;
use common::mm_error::prelude::*;
use common::rusqlite::types::Type;
use common::rusqlite::{Connection, Error as SqlError, NO_PARAMS};
use rpc::v1::types::Bytes as BytesJson;
use serde_json::{self as json};
use std::sync::{Arc, Mutex};

fn validate_table_name(table_name: &str) -> Result<(), MmError<SqlError>> {
    // As per https://stackoverflow.com/a/3247553, tables can't be the target of parameter substitution.
    // So we have to use a plain concatenation disallowing any characters in the table name that may lead to SQL injection.
    if table_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Ok(())
    } else {
        MmError::err(SqlError::InvalidParameterName(table_name.to_string()))
    }
}

fn create_tx_history_table_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "CREATE TABLE IF NOT EXISTS ".to_owned()
        + table_name
        + " (
        id INTEGER NOT NULL PRIMARY KEY,
        tx_hash VARCHAR(255) NOT NULL,
        internal_id VARCHAR(255) NOT NULL UNIQUE,
        block_height INTEGER NOT NULL,
        confirmation_status INTEGER NOT NULL,
        token_id VARCHAR(255) NOT NULL,
        details_json TEXT
    );";

    Ok(sql)
}

fn insert_tx_into_table_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "INSERT INTO ".to_owned()
        + table_name
        + " (tx_hash, internal_id, block_height, confirmation_status, token_id, details_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6);";

    Ok(sql)
}

fn remove_tx_from_table_by_internal_id_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "DELETE FROM ".to_owned() + table_name + " WHERE internal_id=?1;";

    Ok(sql)
}

fn select_tx_from_table_by_internal_id_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "SELECT details_json FROM ".to_owned() + table_name + " WHERE internal_id=?1;";

    Ok(sql)
}

fn update_tx_in_table_by_internal_id_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "UPDATE ".to_owned()
        + table_name
        + " SET block_height = ?1, confirmation_status = ?2, details_json = ?3 WHERE internal_id=?4;";

    Ok(sql)
}

fn contains_unconfirmed_transactions_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "SELECT COUNT(id) FROM ".to_owned() + table_name + " WHERE confirmation_status = 0;";

    Ok(sql)
}

fn get_unconfirmed_transactions_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "SELECT details_json FROM ".to_owned() + table_name + " WHERE confirmation_status = 0;";

    Ok(sql)
}

fn has_transactions_with_hash_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "SELECT COUNT(id) FROM ".to_owned() + table_name + " WHERE tx_hash = ?1;";

    Ok(sql)
}

fn unique_tx_hashes_num_sql(table_name: &str) -> Result<String, MmError<SqlError>> {
    validate_table_name(table_name)?;

    let sql = "SELECT COUNT(DISTINCT tx_hash) FROM ".to_owned() + table_name + ";";

    Ok(sql)
}

#[derive(Clone)]
pub struct SqliteTxHistoryStorage(pub Arc<Mutex<Connection>>);

#[cfg(test)]
impl SqliteTxHistoryStorage {
    fn in_memory() -> Self { SqliteTxHistoryStorage(Arc::new(Mutex::new(Connection::open_in_memory().unwrap()))) }

    fn is_table_empty(&self, table: &str) -> bool {
        validate_table_name(table).unwrap();
        let sql = "SELECT COUNT(id) FROM ".to_owned() + table + ";";
        let conn = self.0.lock().unwrap();
        let rows_count: u32 = conn.query_row(&sql, NO_PARAMS, |row| row.get(0)).unwrap();
        rows_count == 0
    }
}

#[async_trait]
impl TxHistoryStorage for SqliteTxHistoryStorage {
    type Error = SqlError;

    async fn init_collection(&self, collection_id: &str) -> Result<(), MmError<SqlError>> {
        let selfi = self.clone();
        let sql = create_tx_history_table_sql(collection_id)?;
        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            conn.execute(&sql, NO_PARAMS).map(|_| ()).map_err(MmError::new)
        })
        .await
    }

    async fn add_transaction(
        &self,
        collection_id: &str,
        transaction: &TransactionDetails,
    ) -> Result<(), MmError<SqlError>> {
        let tx_hash = format!("{:02x}", transaction.tx_hash);
        let internal_id = format!("{:02x}", transaction.internal_id);
        let confirmation_status = if transaction.block_height > 0 { 1 } else { 0 };
        let token_id = if let TransactionType::TokenTransfer(token_id) = &transaction.transaction_type {
            format!("{:02x}", token_id)
        } else {
            "".to_owned()
        };
        let tx_json = json::to_string(&transaction).unwrap();

        let params = [
            tx_hash,
            internal_id,
            transaction.block_height.to_string(),
            confirmation_status.to_string(),
            token_id,
            tx_json,
        ];
        let sql = insert_tx_into_table_sql(collection_id)?;

        let selfi = self.clone();
        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            conn.execute(&sql, params).map(|_| ()).map_err(MmError::new)
        })
        .await
    }

    async fn add_transactions(
        &self,
        collection_id: &str,
        transactions: impl IntoIterator<Item = TransactionDetails> + Send + 'static,
    ) -> Result<(), MmError<SqlError>> {
        let collection_id = collection_id.to_owned();
        let selfi = self.clone();

        async_blocking(move || {
            let mut conn = selfi.0.lock().unwrap();
            let sql_transaction = conn.transaction()?;

            for tx in transactions {
                let tx_hash = format!("{:02x}", tx.tx_hash);
                let internal_id = format!("{:02x}", tx.internal_id);
                let confirmation_status = if tx.block_height > 0 { 1 } else { 0 };
                let token_id = if let TransactionType::TokenTransfer(token_id) = &tx.transaction_type {
                    format!("{:02x}", token_id)
                } else {
                    "".to_owned()
                };
                let tx_json = json::to_string(&tx).expect("serialization should not fail");

                let params = [
                    tx_hash,
                    internal_id,
                    tx.block_height.to_string(),
                    confirmation_status.to_string(),
                    token_id,
                    tx_json,
                ];

                sql_transaction.execute(&insert_tx_into_table_sql(&collection_id)?, &params)?;
            }
            sql_transaction.commit()?;
            Ok(())
        })
        .await
    }

    async fn remove_transaction(
        &self,
        collection_id: &str,
        internal_tx_id: &BytesJson,
    ) -> Result<RemoveTxResult, MmError<SqlError>> {
        let sql = remove_tx_from_table_by_internal_id_sql(collection_id)?;
        let params = [format!("{:02x}", internal_tx_id)];
        let selfi = self.clone();

        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            conn.execute(&sql, &params)
                .map(|rows_num| {
                    if rows_num > 0 {
                        RemoveTxResult::TxRemoved
                    } else {
                        RemoveTxResult::TxDidNotExist
                    }
                })
                .map_err(MmError::new)
        })
        .await
    }

    async fn get_transaction(
        &self,
        collection_id: &str,
        internal_tx_id: &BytesJson,
    ) -> Result<Option<TransactionDetails>, MmError<SqlError>> {
        let params = [format!("{:02x}", internal_tx_id)];
        let sql = select_tx_from_table_by_internal_id_sql(collection_id)?;
        let selfi = self.clone();

        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            let maybe_json_string = conn.query_row::<String, _, _>(&sql, &params, |row| row.get(0));
            if let Err(SqlError::QueryReturnedNoRows) = maybe_json_string {
                return Ok(None);
            }

            let json_string = maybe_json_string?;
            let tx_details = json::from_str(&json_string)
                .map_err(|e| SqlError::FromSqlConversionFailure(0, Type::Text, Box::new(e)))?;

            Ok(Some(tx_details))
        })
        .await
    }

    async fn contains_unconfirmed_transactions(&self, collection_id: &str) -> Result<bool, MmError<Self::Error>> {
        let sql = contains_unconfirmed_transactions_sql(collection_id)?;
        let selfi = self.clone();

        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            let count_unconfirmed = conn.query_row::<u32, _, _>(&sql, NO_PARAMS, |row| row.get(0))?;
            Ok(count_unconfirmed > 0)
        })
        .await
    }

    async fn get_unconfirmed_transactions(
        &self,
        collection_id: &str,
    ) -> Result<Vec<TransactionDetails>, MmError<Self::Error>> {
        let sql = get_unconfirmed_transactions_sql(collection_id)?;
        let selfi = self.clone();

        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query(NO_PARAMS)?;
            let result = rows
                .mapped(|row| {
                    let string: String = row.get(0)?;
                    json::from_str(&string).map_err(|e| SqlError::FromSqlConversionFailure(0, Type::Text, Box::new(e)))
                })
                .collect::<Result<_, _>>()?;
            Ok(result)
        })
        .await
    }

    async fn update_transaction(
        &self,
        collection_id: &str,
        tx: &TransactionDetails,
    ) -> Result<(), MmError<Self::Error>> {
        let sql = update_tx_in_table_by_internal_id_sql(collection_id)?;

        let block_height = tx.block_height.to_string();
        let confirmation_status = if tx.block_height > 0 { 1 } else { 0 };
        let json_details = json::to_string(tx).unwrap();
        let internal_id = format!("{:02x}", tx.internal_id);

        let params = [block_height, confirmation_status.to_string(), json_details, internal_id];

        let selfi = self.clone();
        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            conn.execute(&sql, params).map(|_| ()).map_err(MmError::new)
        })
        .await
    }

    async fn has_transactions_with_hash(
        &self,
        collection_id: &str,
        tx_hash: &str,
    ) -> Result<bool, MmError<Self::Error>> {
        let sql = has_transactions_with_hash_sql(collection_id)?;
        let params = [tx_hash.to_owned()];

        let selfi = self.clone();
        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            let count: u32 = conn.query_row(&sql, params, |row| row.get(0))?;
            Ok(count > 0)
        })
        .await
    }

    async fn unique_tx_hashes_num(&self, collection_id: &str) -> Result<usize, MmError<Self::Error>> {
        let sql = unique_tx_hashes_num_sql(collection_id)?;
        let selfi = self.clone();
        async_blocking(move || {
            let conn = selfi.0.lock().unwrap();
            let count: u32 = conn.query_row(&sql, NO_PARAMS, |row| row.get(0))?;
            Ok(count as usize)
        })
        .await
    }
}

#[cfg(test)]
mod sql_tx_history_storage_tests {
    use super::*;
    use common::block_on;

    #[test]
    fn test_init_collection() {
        let storage = SqliteTxHistoryStorage::in_memory();
        block_on(storage.init_collection("test_collection")).unwrap();
        // repetitive init must not fail
        block_on(storage.init_collection("test_collection")).unwrap();
    }

    #[test]
    fn test_add_transaction() {
        let storage = SqliteTxHistoryStorage::in_memory();
        let collection = "test_collection_for_add";

        block_on(storage.init_collection(collection)).unwrap();
        let tx_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        block_on(storage.add_transaction(collection, &json::from_str(tx_json).unwrap())).unwrap();

        // next attempt must fail because internal id is unique
        block_on(storage.add_transaction(collection, &json::from_str(tx_json).unwrap())).unwrap_err();
    }

    #[test]
    fn test_add_transactions() {
        let storage = SqliteTxHistoryStorage::in_memory();
        let collection = "test_collection_for_add_transactions";

        block_on(storage.init_collection(collection)).unwrap();
        let tx1_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        let tx1: TransactionDetails = json::from_str(&tx1_json).unwrap();
        let transactions = [tx1.clone(), tx1.clone()];

        // must fail because we are adding transactions with the same internal_id
        block_on(storage.add_transactions(collection, transactions)).unwrap_err();
        assert!(storage.is_table_empty(collection));

        let tx2_json = r#"{"tx_hex":"0400008085202f890158d6bccb2141e18633171f631f594b7f1ae85985390b534733ea5be4da220426030000006b483045022100895dea201a1dc59480d59790569df8664cf3d1d9332efeea7dcc38b4a96399b402206c183f33a3e87eb473a7d3da1488ee9a7d9580cfc86cc8460c79a69c08818478012102d09f2cb1693be9c0ea73bb48d45ce61805edd1c43590681b02f877206078a5b3ffffffff0400e1f505000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac00c2eb0b000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588aca01f791c000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac500df208ed0000001976a91490a0d8ba62c339ade97a14e81b6f531de03fdbb288ac00000000000000000000000000000000000000","tx_hash":"8d61223938c56ca97e9a0e1a295734c5f7b9dba8e4e0c1c638125190e7e796fa","from":["RNTv4xTLLm26p3SvsQCBy9qNK7s1RgGYSB"],"to":["RNTv4xTLLm26p3SvsQCBy9qNK7s1RgGYSB","RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10188.3504","spent_by_me":"0","received_by_me":"7.777","my_balance_change":"7.777","block_height":793474,"timestamp":1612780908,"fee_details":{"type":"Utxo","amount":"0.0001"},"coin":"RICK","internal_id":"8d61223938c56ca97e9a0e1a295734c5f7b9dba8e4e0c1c638125190e7e796fa"}"#;
        let tx2 = json::from_str(tx2_json).unwrap();
        let transactions = [tx1, tx2];
        block_on(storage.add_transactions(collection, transactions)).unwrap();
        assert!(!storage.is_table_empty(collection));
    }

    #[test]
    fn test_remove_transaction() {
        let storage = SqliteTxHistoryStorage::in_memory();
        let collection = "test_collection_for_remove";

        block_on(storage.init_collection(collection)).unwrap();
        let tx_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        block_on(storage.add_transaction(collection, &json::from_str(tx_json).unwrap())).unwrap();

        let remove_res = block_on(storage.remove_transaction(
            collection,
            &"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c".into(),
        ))
        .unwrap();
        assert!(remove_res.tx_existed());

        let remove_res = block_on(storage.remove_transaction(
            collection,
            &"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c".into(),
        ))
        .unwrap();
        assert!(!remove_res.tx_existed());
    }

    #[test]
    fn test_get_transaction() {
        let collection = "test_collection_for_get_tx";
        let storage = SqliteTxHistoryStorage::in_memory();
        block_on(storage.init_collection(collection)).unwrap();

        let tx_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        block_on(storage.add_transaction(collection, &json::from_str(tx_json).unwrap())).unwrap();

        let tx = block_on(storage.get_transaction(
            collection,
            &"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c".into(),
        ))
        .unwrap()
        .unwrap();
        println!("{:?}", tx);

        block_on(storage.remove_transaction(
            collection,
            &"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c".into(),
        ))
        .unwrap();

        let tx = block_on(storage.get_transaction(
            collection,
            &"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c".into(),
        ))
        .unwrap();
        assert!(tx.is_none());
    }

    #[test]
    fn test_update_transaction() {
        let collection = "test_collection_for_update";
        let storage = SqliteTxHistoryStorage::in_memory();
        block_on(storage.init_collection(collection)).unwrap();

        let tx_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        let mut tx_details = json::from_str(tx_json).unwrap();
        block_on(storage.add_transaction(collection, &tx_details)).unwrap();

        tx_details.block_height = 12345;

        block_on(storage.update_transaction(collection, &tx_details)).unwrap();

        let updated = block_on(storage.get_transaction(collection, &tx_details.internal_id))
            .unwrap()
            .unwrap();

        assert_eq!(12345, updated.block_height);
    }

    #[test]
    fn test_contains_and_get_unconfirmed_transaction() {
        let collection = "test_collection_for_unconfirmed";
        let storage = SqliteTxHistoryStorage::in_memory();
        block_on(storage.init_collection(collection)).unwrap();

        let tx_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        let mut tx_details: TransactionDetails = json::from_str(tx_json).unwrap();
        tx_details.block_height = 0;
        block_on(storage.add_transaction(collection, &tx_details)).unwrap();

        let contains_unconfirmed = block_on(storage.contains_unconfirmed_transactions(collection)).unwrap();
        assert!(contains_unconfirmed);

        let unconfirmed_transactions = block_on(storage.get_unconfirmed_transactions(collection)).unwrap();
        assert_eq!(unconfirmed_transactions.len(), 1);

        tx_details.block_height = 12345;
        block_on(storage.update_transaction(collection, &tx_details)).unwrap();

        let contains_unconfirmed = block_on(storage.contains_unconfirmed_transactions(collection)).unwrap();
        assert!(!contains_unconfirmed);

        let unconfirmed_transactions = block_on(storage.get_unconfirmed_transactions(collection)).unwrap();
        assert!(unconfirmed_transactions.is_empty());
    }

    #[test]
    fn test_has_transactions_with_hash() {
        let collection = "test_collection_for_has_transactions_with_hash";
        let storage = SqliteTxHistoryStorage::in_memory();
        block_on(storage.init_collection(collection)).unwrap();

        assert!(!block_on(storage.has_transactions_with_hash(
            collection,
            "2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"
        ))
        .unwrap());

        let tx_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        let tx_details: TransactionDetails = json::from_str(tx_json).unwrap();

        block_on(storage.add_transaction(collection, &tx_details)).unwrap();

        assert!(block_on(storage.has_transactions_with_hash(
            collection,
            "2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"
        ))
        .unwrap());
    }

    #[test]
    fn test_unique_tx_hashes_num() {
        let collection = "test_collection_for_unique_tx_hashes_num";
        let storage = SqliteTxHistoryStorage::in_memory();
        block_on(storage.init_collection(collection)).unwrap();

        let tx1_json = r#"{"tx_hex":"0400008085202f890708b189a2d740a74042541fe687a8d698b7a00c1bfdaf0c708b6bb32f8f7307aa000000006946304302201529f09fdf9177e8b5e2d494488da1e49ec7c1b85a457871e1a78df4e3ba0541021f74538866128b21ed0b77701289ad49ee9a74f8349b9670f73cf6babc4a8ce5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff6403323bb3cd025754336cad57ddc36aedb56107a7a1c6f6ddbfbc893c69d556000000006a4730440220560b8d87f3f020856d3e4704be15a307aa8a49290bf7a8e27a66fc0436e3eb9c0220585c1705a701a669b6b53dae2aad2729786590fbbfbb8f7998bb22e38b60c2d5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff1c5f114649d5194b15502f286d337e03ca7fc3eb0798bc91e6006a645c525f96000000006a473044022078439f12c288d9d694820dbff1e1ceb592be28f7b7e9ba91c73af8110b171c3f02200c8a061f3d48daefaeed40e667543693bb5f206e58fa15b93808e2ecf762ec2f012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff322a446b2373782c727e2f83a914707d5f8af8fd4f4db34243c7223d438f5f5000000006b483045022100dd101b16dfbe02201768eab2bbbd9df40e56a565492b38e7304284385f04cccf02207ac4e8f1aa768162d24a9b1fb73df0771f34942c2120f980228961e9fcb338ea012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d000000006a47304402207c539bcb32efe7a13f1ff6a7b44a5dce4f794a3af7009eb960a65b03214f2fa102204bc3cddc50c8042c2f852a18c0c68107418ac692f0984c3e7ec2f2d1bf23adf5012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d010000006b4830450221009170c72f25f68e9200b398695e9f6edc706b868d75f7a1e194e068ac1377c95e02206265bb27fcf97fa0d13842d49772bd4b37b8661592df6d7fcec5b7e6c828ecf7012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffffa96e7e790511238c6c1e0e4a8dbb9f7c53457291a0e9a7ea96cc5383922618d020000006a47304402206dce88dc192623e69a17cc56609872c75e35b5c608ffeaa31f6df70b09ddbd5302206cf9688439b2192ba57d72af024855741bf77a2a58acf10e5eddfcc36fe7be74012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0198e8d440000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac59cbb060000000000000000000000000000000","tx_hash":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c","from":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"to":["RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10.87696","spent_by_me":"10.87696","received_by_me":"10.87695","my_balance_change":"-0.00001","block_height":949554,"timestamp":1622199314,"fee_details":{"type":"Utxo","amount":"0.00001"},"coin":"RICK","internal_id":"2c33baf0c40eebcb70fc22eab0158e315e2176e4a3f20acddcd849186fca492c"}"#;
        let tx1: TransactionDetails = json::from_str(&tx1_json).unwrap();

        let mut tx2 = tx1.clone();
        tx2.internal_id = BytesJson(vec![1; 32]);

        let tx3_json = r#"{"tx_hex":"0400008085202f890158d6bccb2141e18633171f631f594b7f1ae85985390b534733ea5be4da220426030000006b483045022100895dea201a1dc59480d59790569df8664cf3d1d9332efeea7dcc38b4a96399b402206c183f33a3e87eb473a7d3da1488ee9a7d9580cfc86cc8460c79a69c08818478012102d09f2cb1693be9c0ea73bb48d45ce61805edd1c43590681b02f877206078a5b3ffffffff0400e1f505000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac00c2eb0b000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588aca01f791c000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac500df208ed0000001976a91490a0d8ba62c339ade97a14e81b6f531de03fdbb288ac00000000000000000000000000000000000000","tx_hash":"8d61223938c56ca97e9a0e1a295734c5f7b9dba8e4e0c1c638125190e7e796fa","from":["RNTv4xTLLm26p3SvsQCBy9qNK7s1RgGYSB"],"to":["RNTv4xTLLm26p3SvsQCBy9qNK7s1RgGYSB","RUjPst697T7ahtF8EpZ1whpAmJZfqfwW36"],"total_amount":"10188.3504","spent_by_me":"0","received_by_me":"7.777","my_balance_change":"7.777","block_height":793474,"timestamp":1612780908,"fee_details":{"type":"Utxo","amount":"0.0001"},"coin":"RICK","internal_id":"8d61223938c56ca97e9a0e1a295734c5f7b9dba8e4e0c1c638125190e7e796fa"}"#;
        let tx3 = json::from_str(tx3_json).unwrap();

        let transactions = [tx1, tx2, tx3];
        block_on(storage.add_transactions(collection, transactions)).unwrap();

        let tx_hashes_num = block_on(storage.unique_tx_hashes_num(collection)).unwrap();
        assert_eq!(2, tx_hashes_num);
    }
}
