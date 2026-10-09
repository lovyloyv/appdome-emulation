# Appdome Android Emulation

This repository contains the code, images, and anonymized samples accompanying research into Appdome's Android application dependencies: initialization, Java string restoration, native-method registration, and packed native exports.

[The full investigation is present at my blog.](https://lovy.sh/posts/appdome-emulation/)

## Repository contents

| Directory | Contents |
| --- | --- |
| [poc/](poc/README.md) | Replacement library and a guide to the source |
| [assets/images/](assets/images/README.md) | Identifier-redacted screenshots used by the article |
| [assets/samples/](assets/samples/README.md) | Anonymized evidence files, recovered classes, and extracted-blob archives cited by the article |

I worked on this from February to April 2026 and tested on ARM64. This is the research implementation; expect to adapt it for other protected builds.

I've masked identifying text in the screenshots and renamed identifiers in the samples. The samples are there to follow the analysis; renamed assets may no longer match their original hashes. Original files and private working notes are excluded from this repository.

The article focuses on assets, initialization, and native exports. It leaves detections aside and closes with defense ideas I haven't tested yet.
