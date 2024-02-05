use std::{fmt, str};

use serde::{Deserialize, Serialize};

use crate::error::RosaError;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum DistanceMetric {
    Hamming,
}

impl DistanceMetric {
    pub fn dist(&self, v1: &[u8], v2: &[u8]) -> u64 {
        match self {
            Self::Hamming => hamming(v1, v2),
        }
    }
}

impl fmt::Display for DistanceMetric {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Hamming => "hamming",
            }
        )
    }
}

impl str::FromStr for DistanceMetric {
    type Err = RosaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hamming" => Ok(Self::Hamming),
            unknown => fail!("invalid distance metric '{}'.", unknown),
        }
    }
}

fn hamming(v1: &[u8], v2: &[u8]) -> u64 {
    assert_eq!(v1.len(), v2.len(), "vector length mismatch.");

    v1.iter()
        .zip(v2.iter())
        .fold(0, |acc, (item1, item2)| acc + ((item1 ^ item2) as u64))
}
