package main

test_deny_under_21 {
    deny["Use version 2.1 or higher"] with input as {"version": 2}
}

test_allow_version_21 {
    not deny["Use version 2.1 or higher"] with input as {"version": 2.1}
}

test_deny_dlc_docker {
    deny["Don't use DLC"] with input as 
    {
        "version": 2.1,
        "jobs": {
            "build": {
                "steps": [
                    "checkout",
                    {
                        "setup_remote_docker": {
                            "docker_layer_caching": true,
                        },
                    },
                    {
                        "run": {
                            "docker build .",
                        }
                    }
                ],
            }
        }
    }
}

test_allow_dlc_docker_not_in_use {
    not deny["Don't use DLC"] with input as 
    {
        "version": 2.1,
        "jobs": {
            "build": {
                "steps": [
                    "checkout",
                    {
                        "run": {
                            "foo bar",
                        }
                    }
                ],
            }
        }
    }
}


test_allow_dlc_docker_not_in_use {
    not deny["Don't use DLC"] with input as 
    {
        "version": 2.1,
        "jobs": {
            "hogefuga": {
                "steps": [
                    "checkout",
                    {
                        "setup_remote_docker": {
                            "docker_layer_caching": false,
                        },
                    },
                    {
                        "run": {
                            "foo bar",
                        }
                    }
                ],
            }
        }
    }
}


test_deny_dlc_machine {
    deny["Don't use DLC"] with input as 
    {
        "version": 2,
        "jobs": {
            "make": {
                "machine": {
                    "docker_layer_caching": true
                }
            }
        }
    }
}