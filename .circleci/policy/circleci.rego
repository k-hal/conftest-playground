package main

deny[msg] {
 input.version < 2.1
 msg = "Use version 2.1 or higher"
}

deny[msg] {
    input.jobs[_].machine.docker_layer_caching == true
    msg = "Don't use DLC"
}

deny[msg] {
    input.jobs[_].steps[_].setup_remote_docker.docker_layer_caching == true
    msg = "Don't use DLC"
}
