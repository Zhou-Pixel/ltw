use std::fs::File;
use std::io;

pub struct LogOutput {
    outputs: Vec<Box<dyn io::Write + Send + 'static>>,
}

impl Default for LogOutput {
    fn default() -> Self {
        let current_path = std::env::current_dir().unwrap().into_os_string().into_string().unwrap();
        let file = File::create("./ltwc_log.txt").expect(format!("Open file {}/ntlc_log.txt failed", current_path).as_str());
        // let f : Box<dyn io::Write + Send + 'static> = Box::new(file);
        Self {
            outputs: vec![Box::new(file), Box::new(io::stdout())],
        }
    }
}

impl io::Write for LogOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut max = 0;
        for i in 0..self.outputs.len() {
            let tmp = self.outputs[i].as_mut().write(buf)?;
            if tmp > max {
                max = tmp;
            }
        }
        Ok(max)
    }

    fn flush(&mut self) -> io::Result<()> {
        for i in 0..self.outputs.len() {
            self.outputs[i].as_mut().flush()?;
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