# Contributors Guide

Lighthouse is an open-source Ethereum 2.0 client. We we're community driven and
welcome all contribution. We aim to provide a constructive, respectful and fun
environment for collaboration.

We are active contributors to the [Ethereum 2.0 specification](https://github.com/ethereum/eth2.0-specs) and attend all [Eth
2.0 implementers calls](https://github.com/ethereum/eth2.0-pm).

This guide is geared towards beginners. If you're an open-source veteran feel
free to just skim this document and get straight into crushing issues.

## Why Contribute

There are many reasons you might contribute to Lighthouse. For example, you may
wish to:

- contribute to the Ethereum ecosystem.
- establish yourself as a layer-1 Ethereum developer.
- work in the amazing Rust programming language.
- learn how to participate in open-source projects.
- expand your software development skills.
- flex your skills in a public forum to expand your career
  opportunities (or simply for the fun of it).
- grow your network by working with core Ethereum developers.

## How to Contribute

Regardless of the reason, the process to begin contributing is very much the
same. We operate like a typical open-source project operating on GitHub: the
repository [Issues](https://github.com/sigp/lighthouse/issues) is where we
track what needs to be done and [Pull
Requests](https://github.com/sigp/lighthouse/pulls) is where code gets
reviewed. We use [gitter](https://gitter.im/sigp/lighthouse) to chat
informally.

### General Work-Flow

We recommend the following work-flow for contributors:

1. **Find an issue** to work on, either because it's interesting or suitable to
   your skill-set. Use comments to communicate your intentions and ask
questions.
2. **Work in a feature branch** of your personal fork
   (github.com/YOUR_NAME/lighthouse) of the main repository
   (github.com/sigp/lighthouse).
3. Once you feel you have addressed the issue, **create a pull-request** to merge
   your changes in to the main repository.
4. Wait for the repository maintainers to **review your changes** to ensure the
   issue is addressed satisfactorily. Optionally, mention your PR on
[gitter](https://gitter.im/sigp/lighthouse).
5. If the issue is addressed the repository maintainers will **merge your
   pull-request** and you'll be an official contributor!

Generally, you find an issue you'd like to work on and announce your intentions
to start work in a comment on the issue. Then, do your work on a separate
branch (a "feature branch") in your own fork of the main repository.  Once
you're happy and you think the issue has been addressed, create a pull request
into the main repository.

### First-time Set-up

First time contributors can get their git environment up and running with these
steps:

1. [Create a
   fork](https://help.github.com/articles/fork-a-repo/#fork-an-example-repository)
and [clone
it](https://help.github.com/articles/fork-a-repo/#step-2-create-a-local-clone-of-your-fork)
to your local machine.
2. [Add an _"upstream"_
   branch](https://help.github.com/articles/fork-a-repo/#step-3-configure-git-to-sync-your-fork-with-the-original-spoon-knife-repository)
that tracks github.com/sigp/lighthouse using `$ git remote add upstream
https://github.com/sigp/lighthouse.git` (pro-tip: [use SSH](https://help.github.com/articles/connecting-to-github-with-ssh/) instead of HTTPS).
3. Create a new feature branch with `$ git checkout -b your_feature_name`. The
   name of your branch isn't critical but it should be short and instructive.
E.g., if you're fixing a bug with serialization, you could name your branch
`fix_serialization_bug`.
4. Commit your changes and push them to your fork with `$ git push origin
   your_feature_name`.
5. Go to your fork on github.com and use the web interface to create a pull
   request into the sigp/lighthouse repo.

From there, the repository maintainers will review the PR and either accept it
or provide some constructive feedback.

There's great
[guide](https://akrabat.com/the-beginners-guide-to-contributing-to-a-github-project/)
by Rob Allen that provides much more detail on each of these steps, if you're
having trouble. As always, jump on [gitter](https://gitter.im/sigp/lighthouse)
if you get stuck.


## FAQs

### I don't think I have anything to add

There's lots to be done and there's all sorts of tasks. You can do anything
from correcting typos through to writing core consensus code. If you reach out,
we'll include you.

### I'm not sure my Rust is good enough

We're open to developers of all levels. If you create a PR and your code
doesn't meet our standards, we'll help you fix it and we'll share the reasoning
with you. Contributing to open-source is a great way to learn.

### I'm not sure I know enough about Ethereum 2.0

No problems, there's plenty of tasks that don't require extensive Ethereum
knowledge. You can learn about Ethereum as you go.

### I'm afraid of making a mistake and looking silly

Don't be. We're all about personal development and constructive feedback. If you
make a mistake and learn from it, everyone wins.

### I don't like the way you do things

Please, make an issue and explain why. We're open to constructive criticism and
will happily change our ways.
