use proto_array::fork_choice_test_definition::*;
use std::fs::File;

fn main() {
    write_test_def_to_yaml("votes.yaml", get_votes_test_definition());
    write_test_def_to_yaml("no_votes.yaml", get_no_votes_test_definition());
    write_test_def_to_yaml("ffg_01.yaml", get_ffg_case_01_test_definition());
    write_test_def_to_yaml("ffg_02.yaml", get_ffg_case_02_test_definition());
    write_test_def_to_yaml(
        "execution_status_01.yaml",
        get_execution_status_test_definition_01(),
    );
    write_test_def_to_yaml(
        "execution_status_02.yaml",
        get_execution_status_test_definition_02(),
    );
    write_test_def_to_yaml(
        "execution_status_03.yaml",
        get_execution_status_test_definition_03(),
    );
}

fn write_test_def_to_yaml(filename: &str, def: ForkChoiceTestDefinition) {
    let file = File::create(filename).expect("Should be able to open file");
    serde_yaml::to_writer(file, &def).expect("Should be able to write YAML to file");
}
