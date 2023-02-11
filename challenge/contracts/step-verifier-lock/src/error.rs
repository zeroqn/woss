use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing = 2,
    LengthNotEnough = 3,
    Encoding = 4,
    // Add customized errors here...
    InvalidWitness = 5,
    InvalidStepProof = 6,
    InvalidLockArgs = 7,
    VerifierCommit = 8,
    MismatchStepCommitment = 9,
    ExecuteNextStep = 10,
    MismatchNextStepCommitment = 11,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}
