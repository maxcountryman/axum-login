#[cfg(feature = "sqlite-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlite-store")))]
mod sqlite_store;

#[cfg(feature = "sqlite-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlite-store")))]
pub use self::sqlite_store::SqliteUserStore;

pub trait DefaultQueryProvider {
    fn default_query() -> String;
}
