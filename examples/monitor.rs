use routex::{RouteAction, RouteSock};

fn main() {
    let mut handle = RouteSock::new().unwrap();

    #[cfg(target_os = "linux")]
    handle.subscript().unwrap();   

    let mut buf = RouteSock::new_buf();

    loop {
        let ret = handle.monitor(&mut buf).unwrap();
        println!("{:?}", ret);
        match ret.0 {
            routex::RouteChange::ADD => {
                let route = ret.1;
                if route.destination.is_unspecified() {
                    println!("default route added: {:?}", route);
                }
            }
            routex::RouteChange::OTHER(n) if n == 0xc/* RTM_NEWADDR */ => {
                let route = ret.1;
                if route.destination.is_unspecified() {
                    println!("default addr added: {:?}", route);
                }
            },
            _ => ()
        }
    }
}
