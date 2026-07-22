use routex::{RouteAction, RouteSock};

fn main() {
    let mut handle = RouteSock::new().unwrap();

    #[cfg(target_os = "linux")]
    handle.subscribe().unwrap();

    let mut buf = RouteSock::new_buf();

    loop {
        let ret = handle.monitor(&mut buf).unwrap();
        println!("{:?}", ret);
        if let routex::RouteChange::ADD = ret.0 {
            let route = ret.1;
            if route.destination.is_unspecified() {
                println!("default route added: {:?}", route);
            }
        }
    }
}
