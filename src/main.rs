use obfuscator::obfuscated;

fn junk_test() {
    println!("This is a test function with junk code.");
}

fn kontrol_et(sayi: i32) {
    if sayi > 0 {
        println!("Sayı pozitif!");
    } else if sayi < 0 {
        println!("Sayı negatif!");
    } else {
        println!("Sayı sıfır!");
    }
}

fn main() {
    junk_test();
	kontrol_et(10);
    println!("{}", obfuscated!("sadxas"));
}
