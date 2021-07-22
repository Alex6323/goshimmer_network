use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "shimmer", about = "Shimmer network usage.")]
pub struct CliArgs {
    #[structopt(short, long)]
    pub port: u16,

    #[structopt(short, long)]
    pub identity: Option<String>,
}
