use rand;
use rand::distributions::uniform::SampleUniform;
use rand::distributions::Distribution;
use rand::distributions::Standard;
use rand::{thread_rng, Rng};
use std::net::Ipv4Addr;

/// A very fast but not secure guaranteed random number generator by using [Xorshift algorithm](https://en.wikipedia.org/wiki/Xorshift)
///
/// Same usage as `rand::random()`.
pub fn fast_random<T>() -> Result<T, rand::Error>
where
    T: PartialOrd + SampleUniform,
    Standard: Distribution<T>,
{
    let mut rng = thread_rng();
    //let mut rng = XorShiftRng::from_rng(EntropyRng::new())?;
    Ok(rng.gen())
}

/// Generate random IPv4 address by calling `fast_random`
pub fn rand_ipv4() -> Result<Ipv4Addr, rand::Error> {
    Ok(Ipv4Addr::new(
        fast_random::<u8>()?,
        fast_random::<u8>()?,
        fast_random::<u8>()?,
        fast_random::<u8>()?,
    ))
}
