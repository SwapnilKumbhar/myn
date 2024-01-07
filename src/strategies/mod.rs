// Strategy Modules
pub mod pam_login;

pub enum AuthenticationError {
    NotImplemented,
    StrategyInitFailed,
    AuthenticationFailed,
}

pub trait Strategy<A> {
    fn authenticate(&self, auth_data: A) -> Result<(), AuthenticationError>;
    fn get_name(&self) -> String;
    fn get_description(&self) -> String;
}
