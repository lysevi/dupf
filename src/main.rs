extern crate sha1;

use std::env;
use std::io;
use std::io::prelude::*;
use std::fs::{self, File, DirEntry};
use std::path::Path;
use std::collections::BTreeMap;

use sha1::Sha1;

struct DupFinder {
    hashes: BTreeMap<String, Vec<String>>,
}

impl DupFinder {
    fn new() -> Self {
        DupFinder { hashes: BTreeMap::new() }
    }

    fn print_dups(&self) {
        let mut file = File::create(Path::new("output.csv")).expect("file create error");

        for (k, v) in &self.hashes {
            if v.len() > 1 {
                let msg = format!("{}; {}", k, v.join(";"));
                //file.write(&msg.as_bytes()).expect("write result error");
                println!("{}", msg);

                let key_msg = format!("{};\n", k);
                file.write(&key_msg.as_bytes()).expect("key write error");
                for f in v {
                    let val_msg = format!(";{};\n", f);
                    file.write(&val_msg.as_bytes()).expect("value write error");
                }
            }
        }
    }
    fn cb(&mut self, de: &DirEntry) {
        println!("{} => {}", self.hashes.len(), de.path().display());

        let mut f = File::open(de.path()).expect("file open error");

        let mut contents = String::new();
        let readed_value = f.read_to_string(&mut contents);
        if readed_value.is_err() {
            return;
        }
        let mut m = Sha1::new();
        m.update(&contents.as_bytes());
        let hs = m.digest().to_string();

        let vals: &mut Vec<String> = self.hashes.entry(hs).or_insert(Vec::new());
        vals.push(format!("{}", de.path().display()));
    }

    fn visit_dirs(&mut self, dir: &Path) -> io::Result<()> {
        use std::ffi::OsStr;
        
        let black_list=vec!["vssscc", "vspscc", "exe", "dll", "o", "pdb"];

        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    if path.file_name() != Some(OsStr::new("bin")) &&
                       path.file_name() != Some(OsStr::new("obj")) {
                        self.visit_dirs(&path)?;
                    }
                } else {
                    
                    match path.extension() {
                        Some(extension) => {
                            let mut founded=false;
                            for e in &black_list{
                                if OsStr::new(e) == extension{
                                    founded=true;
                                    break;
                                }
                            }
                            if !founded{
                                self.cb(&entry);
                            }
                        }
                        None => {}
                    }
                }
            }
        }
        Ok(())
    }
}

fn main() {
    if env::args().len() < 2 {
        println!("usage:");
        println!("dup path/to/folder");
        return;
    }
    let root_dir: String = env::args().nth(1).unwrap();

    let mut dv = DupFinder::new();
    dv.visit_dirs(&Path::new(&root_dir))
        .expect("dir read error");
    dv.print_dups();
}
