use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread::{self},
    time::{Duration, Instant},
};

use num_format::{Locale, ToFormattedString};
use worker::worker;

pub mod worker;

fn main() {
    let mut args = std::env::args();
    args.next();

    let prefixes: Vec<String> = args.collect();

    let counter = Arc::new(AtomicUsize::new(0));

    for i in 0..4 {
        let counter_clone = counter.clone();
        let prefixes_clone = prefixes.clone();

        thread::spawn(move || worker(prefixes_clone, counter_clone));

        eprintln!("Started thread {}", i);
    }

    let mut prev_time = Instant::now();
    let mut prev_value = counter.load(Ordering::Relaxed);

    loop {
        let current_value = counter.load(Ordering::Relaxed);
        let elapsed_time = prev_time.elapsed();

        let value_change = current_value - prev_value;

        let rate = value_change as f64 / elapsed_time.as_secs_f64();

        eprintln!(
            "Counter Value: {}, Rate: {} per second",
            current_value.to_formatted_string(&Locale::en),
            (rate as u64).to_formatted_string(&Locale::en)
        );

        prev_value = current_value;
        prev_time = Instant::now();

        thread::sleep(Duration::from_millis(200));
    }
}
