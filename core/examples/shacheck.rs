fn main() {
    for p in std::env::args().skip(1) {
        let mut s = vigil_core::sha256::Sha256::new();
        let data = std::fs::read(&p).expect("read");
        for chunk in data.chunks(64 * 1024) {
            s.update(chunk);
        }
        println!("{}  {}", vigil_core::sha256::hex(&s.finish()), p);
    }
}
