[![build result](https://build.opensuse.org/projects/home:brejoc/packages/gosgp/badge.svg?type=default)](https://build.opensuse.org/package/show/home:brejoc/gosgp)

## gosgp - golang port of supergenpass.com

gosgp is a command line tool to generate SuperGenPass passwords
for a given domain. gosgp won't trim the relevant parts from your
URL string, so please only use domains.

### Usage

    $> gosgp -domain=example.com
    password: 123
    mhn91FJ7Ug

    $> gosgp -domain=github.io
    password: 123
    sGKicH8rFV

### Authors

* Mathias Gumz  <mg@2hoch5.com>   (rework, memory-cleanup, etc)
* Jochen Breuer <brejoc@gmail.com> (initial code)
   note: code posted by Jochen http://paste.dajool.com/p3hfjmoor/zvimni/raw

* Chris Zarate <chris@zarate.org> (supergenpass.com)

### Notes

* gosgp tries to make sure sensitive information is zeroed after use
* gosgp tries to reduce the number of allocations needed
* On systems where memory-locking is not permitted the user might need '-lock=false'
  in order to use gosgp
* Microsoft Windows: locking memory is not implemented atm.
