use std::fs::File;
use std::io;

pub struct LogOutput {
    outputs: Vec<Box<dyn io::Write + Send + 'static>>,
}

impl Default for LogOutput {
    fn default() -> Self {
        let current_path = std::env::current_dir().unwrap().into_os_string().into_string().unwrap();
        let file = File::create("./ltws_log.txt").expect(format!("Open file {}/ntlc_log.txt failed", current_path).as_str());
        // let f : Box<dyn io::Write + Send + 'static> = Box::new(file);
        Self {
            outputs: vec![Box::new(file), Box::new(io::stdout())],
        }
    }
}

impl io::Write for LogOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut max = 0;
        for i in self.outputs.iter_mut() {
            let tmp = i.write(buf)?;
            if tmp > max {
                max = tmp;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        for i in self.outputs.iter_mut() {
            i.flush()?
        }
        Ok(())
    }
}

impl LogOutput {
    pub fn add_file(&mut self, path : &str) {
        let file = File::create(path).expect(format!("Open file :{} failed", path).as_str());
        self.outputs.push(Box::new(file));
    }
    
}