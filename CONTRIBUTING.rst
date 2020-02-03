============
Contributing
============

Contributions are welcome, and they are greatly appreciated! Every
little bit helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------

Report Bugs
~~~~~~~~~~~

Report bugs at https://github.com/PaloAltoNetworks/pandevice/issues.

Fix Bugs
~~~~~~~~

Look through the GitHub issues for bugs. Anything tagged with "bug"
is open to whoever wants to fix it.

Implement Features
~~~~~~~~~~~~~~~~~~

Look through the GitHub issues for features. Anything tagged with "enhancement"
is open to whoever wants to implement it.

Write Documentation
~~~~~~~~~~~~~~~~~~~

Palo Alto Networks Device Framework could always use more documentation, whether as part of the
official Palo Alto Networks Device Framework docs, in docstrings, or even on the web in blog posts,
articles, and such.

The main documentation is in the `docs` directory and the API reference is
generated from docstrings in the code.

After you set up your development environment, type ``poetry run make docs`` to
generate the documentation locally.

Submit Feedback
~~~~~~~~~~~~~~~

The best way to send feedback is to file an issue at https://github.com/PaloAltoNetworks/pandevice/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)

Get Started!
------------

Ready to contribute some code? Here's how to set up `pandevice` for local development.

1. Install python 3.6 or higher

Development must be done using python 3.6 or higher. Development on python 2.7 is
no longer supported.

2. Fork the `pandevice` repo on GitHub.

3. Clone your fork locally::

    $ git clone https://github.com/your-username/pandevice.git

4. Install Poetry

    Poetry is a dependency manager and build tool for python
    If you don't have poetry installed, use the instructions here to install it:

    https://python-poetry.org/docs/#installation

5. Create a virtual environment with dependencies::

    $ poetry install

6. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

7. Now you can make your changes locally

8. When you're done making changes, check that your changes pass flake8 and the tests, including testing other Python versions with tox::

    $ poetry run make lint
    $ poetry run make bandit
    $ poetry run make test
    $ poetry run make test-all
    $ poetry run make sync-deps

9. Commit your changes and push your branch to GitHub::

    $ git add -A
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

10. Submit a pull request through the GitHub website.
