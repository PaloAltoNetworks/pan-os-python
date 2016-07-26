.. :changelog:

History
=======

0.3.5
-----

Released: 2016-07-25

Status: Alpha

Bug fixes and documentation updates

0.3.4
-----

Released: 2016-04-18

Status: Alpha

Added tag variable to the following objects:

* objects.AddressObject
* objects.AddressGroup

0.3.3
-----

Released: 2016-04-15

Status: Alpha

New objects:

* objects.Tag

Updated objects:

* policies.Rulebase

0.3.2
-----

Released: 2016-04-13

Status: Alpha

New objects:

* policies.Rulebase
* policies.PreRulebase
* policies.PostRulebase

0.3.1
-----

Released: 2016-04-12

Status: Alpha

New objects:

* policies.SecurityRule
* objects.AddressGroup

API changes:

* Changed refresh_all to refreshall and apply_all to applyall
* Added insert() method to PanObject base class

Fixes:

* Objects can now be added as children of Panorama which will make them 'shared'
* Fixes for tracebacks
* Minor fixes to documentation and docstrings

0.3.0
-----

Released: 2016-03-30

Status: Alpha

* First release on pypi
* Significant redesign from 0.2.0
* Configuration tree model

0.2.0
-----

Released: 2014-09-17

Status: Pre-alpha

* First release on github
