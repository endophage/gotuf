This is still a work in progress but will shortly be a fully compliant 
Go implementation of [The Update Framework (TUF)](http://theupdateframework.com/).

This implementation was originally forked from [flynn/go-tuf](https://github.com/flynn/go-tuf),
however in attempting to add delegations I found I was making such
significant changes that I could not maintain backwards compatibility
without the code becoming overly convoluted.

This implementation retains the same 3 Clause BSD license present on 
the original flynn implementation.
