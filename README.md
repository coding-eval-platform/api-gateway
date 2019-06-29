
# API Gateway [![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0) [![Build Status](https://img.shields.io/circleci/project/github/coding-eval-platform/api-gateway/master.svg)](https://circleci.com/gh/coding-eval-platform/api-gateway/tree/master) ![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/coding-eval-platform/api-gateway.svg)

Service in charge of providing an entry point into the platform from the outside world, routing external request to each corresponding service.

## Features

- Provide an entry point into the platform
- Route requests to each corresponding service


## Getting started

The following instructions will set the development environment in your local machine, as well as let you run locally an instance of the system.

**Note: This guide covers only Mac OS X setups.**


### Prerequisites

#### Get source code

Clone the repository or download source code:

```
$ git clone https://github.com/coding-eval-platform/api-gateway.git
```
or

```
$ wget https://github.com/coding-eval-platform/api-gateway/archive/master.zip
```

#### Set up Runtime

**This project requires Java 11**. The following is a guide to install Java 11, and optional `jenv` to manage your Java environments.


1.  **Install Java 11:**

    ```
    $ brew cask install java
    ```


    **Note:** If you already had a previous version of Java installed in your system, this will upgrade it. If you want to have several versions of Java installed in your machine, you can use the cask versions tap:


    1.  **Tap the cask versions repository:**

        ```
        $ brew tap homebrew/cask-versions
        ```
    2.  **Install a previous version of Java:**

        ```
        $ brew cask install java8
        ```

2.  **Install and configure jEnv (Optional):**

    Perform this step if you want to run multiple versions of Java in your machine. For more information, check [jEnv webpage](http://www.jenv.be/). Also, check [this guide](https://medium.com/@danielnenkov/multiple-jdk-versions-on-mac-os-x-with-jenv-5ea5522ddc9b).

    1.  **Download software:**

        ```
        $ brew install jenv
        ```

    2.  **Update your `bash` or `zsh` profile to use jEnv:**

        ##### Bash
        ```
        $ echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.bash_profile
        $ echo 'eval "$(jenv init -)"' >> ~/.bash_profile
        ```

        If you want to use jEnv now, don't forget to source again your profile:

        ```
        $ source ~/.bash_profile
        ```

        ##### Zsh
        ```
        $ echo ‘export PATH=”$HOME/.jenv/bin:$PATH”’ >> ~/.zshrc
        $ echo ‘eval “$(jenv init -)”’ >> ~/.zshrc
        ```

        If you want to use jEnv now, don't forget to source again your profile:

        ```
        $ source ~/.zshrc
        ```

    3.  **Locate the JDK installations in your machine. They will likely be in the `/Library/Java/JavaVirtualMachines/` directory.**

    4.  **Add a Java version to jEnv:**

        ```
        $ jenv add /Library/Java/JavaVirtualMachines/{{jdk-version}}/Contents/Home
        ```
        Replace the `{{jdk-version}}` placeholder with an actual version of Java. For example:

        ```
        $ jenv add /Library/Java/JavaVirtualMachines/openjdk-11.0.2.jdk/Contents/Home
        ```

    5.  **Configure jEnv:**

        To set a global version of Java, use the following command:

        ```
        $ jenv global {{jdk-version}}
        ```
        Replace the `{{jdk-version}}` placeholder with an actual version of Java. For example:

        ```
        $ jenv global openjdk-11.0.2.jdk
        ```

        You can check the Java versions being managed by jEnv using the following command:

        ```
        $ jenv versions
        ```

        Similarly, you can set the Java Version with a local or shell scope:

        ##### Local Scope
        If you want to set the Java version for the current working directory:

        ```
        $ jenv local {{jdk-version}}
        ```
        ##### Shell Scope
        If you want to set the Java version for the current session:

        ```
        $ jenv shell {{jdk-version}}
        ```


#### Building tool

The building tool used for the project is Maven.

```
$ brew install maven
```

If you have installed jEnv, you can enable the maven plugin, in order to execute maven using the jEnv managed Java:

```
$ jenv enable-plugin maven
```

Restart your shell session in order to have the plugin running.

Check [this resource](https://github.com/gcuisinier/jenv#plugins) for more information about jEnv plugins.



### Build

1. Install artifacts:

	```
	$ cd <project-root>
	$ mvn clean install
	```

	Doing this will let you access all modules defined in the project scope.

2. Build the project:

	```
	$ mvn clean package
	```

	**Note:** In case you change the `<project-root>/src/main/resources/application.yml`, you must build again the project. Otherwise, if you want to change a property on the fly, use command line properties.


### Run

You can run the application using the following command:

```
$ export API_GATEWAY_VERSION=<project-version>
$ java [-Dkey=value properties] -jar <project-root>/target/api-gateway-$API_GATEWAY_VERSION.jar [--key=value properties]
```

The following is a full example of how to run the application:

```
export API_GATEWAY_VERSION=<project-version>
java \
	-jar <project-root>/target/api-gateway-$API_GATEWAY_VERSION.jar \
	--spring.profiles.active=dev
```



## Use with Docker

This project includes a `Dockerfile` in the project's root, together with the [Spotify's dockerfile maven plugin](https://github.com/spotify/dockerfile-maven).


### Build the image

To create an image to run this project in Docker just package the application with maven, and set the `docker-build` profile.
You just have to run the following command:

```
$ mvn clean package -P docker-build -Ddocker.image.tag=latest
```

The built Docker image will be `itbacep/api-gateway:latest`. You can specify the tag you want.


### Run the project

Once you have built the Docker image, just run the following command:

```
$ docker run -p 8000:8000 itbacep/api-gateway:latest
```

Note that you have to use the same tag you used to create the image.


## CI/CD Workflow

This project is integrated with [CircleCI](https://circleci.com/).

### Pull requests

When a pull request is created, a build will be triggered in CircleCI, which must succeed in order to merge the pull request. This build will just **compile the source code and run tests**.
Note that if still committing to a branch with an open pull request, each push to the said branch will trigger a build.

### Pushes and merges into master
Pushing or merging into `master` will also trigger the **compile** and **test** build in CircleCI. If the build succeeds, this will be followed by a Docker phase: it will build a Docker image and push it into DockerHub. This images will be tagged with the commit's hash.

### Releases
A release is performed by tagging in git. Pushing a tag will also trigger the **compile** and **test** build in CircleCI. If the build succeeds, this will be followed by a Docker phase: it will build a Docker image and push it into DockerHub. This images will be tagged with the git's tag.


## License

Copyright 2019 Bellini & Lobo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


## Authors

* [Juan Marcos Bellini](https://github.com/juanmbellini)
* [Daniel Lobo](https://github.com/lobo)
