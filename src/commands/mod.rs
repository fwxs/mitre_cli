mod attck;

use structopt::StructOpt;


#[derive(StructOpt)]
pub struct MitreCli {
    #[structopt(subcommand)]
    matrix: MitreMatrix
}

#[derive(StructOpt)]
pub enum MitreMatrix {
    Attck(attck::AttckCmd)
}
