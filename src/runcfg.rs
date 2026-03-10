use clap::ArgMatches;

pub(crate) struct RunCfg {
    pub(crate) is_verbose: bool,
    pub(crate) input_file: String,
    pub(crate) output_file: String,
    pub(crate) filter_protocol: Option<String>,
}

impl RunCfg {
    pub(crate) fn from_params(matches: &ArgMatches) -> RunCfg {
        RunCfg {
            is_verbose: matches.get_one::<bool>("verbose").copied().unwrap_or(false),
            input_file: matches
                .get_one::<String>("input")
                .expect("An input file must be specified")
                .clone(),
            output_file: matches
                .get_one::<String>("output")
                .cloned()
                .unwrap_or_else(|| String::from("file.json")),
            filter_protocol: matches.get_one::<String>("filter").cloned(),
        }
    }
}
