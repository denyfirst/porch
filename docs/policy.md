# The organisation's undertakings, and a product's

denyfirst says one thing once, and each product says its own part. This document
is why the two are separate, where each lives, and what a second product has to
do to inherit the first.

The text itself is not here. It is in
[`internal/promises`](../internal/promises/promises.go), and it is served at
`/organisation`. A document that restated it would be the exact fault the split
was made to avoid.

---

## Why two documents rather than one

Two readers arrive with two questions.

Somebody deciding whether to **run** a tool wants to know what it does to the
machine it runs on, what it sends to the hosts it is pointed at, and what it
keeps. Somebody deciding whether to **trust the people** who wrote it wants to
know what those people receive. A single page answering both makes every
sentence something to read twice — *is this about the tool or about them?* — and
the answers that matter most end up buried in the details of one check.

It also does not survive a second product. With two products and one page each,
the organisation's undertakings exist as prose in two places, and two places
drift. The day one copy is improved and the other is not, a reader has two
documents from the same people that do not agree, which is worse evidence than
one vague document. Nobody has to be careless for this to happen; it is what
copies do.

## What goes where

**The organisation's list is about the organisation's own conduct**: what it
receives, what it holds, what it publishes, and how what it publishes can be
checked. Nothing in it describes what any product measures.

That line is not tidiness. This organisation has more than one product and they
are built by different hands. An undertaking at the organisation level that
described a product's behaviour would be one repository promising on behalf of
code it cannot see — which is how a policy becomes untrue without anybody
lying.

**A product's list is narrower than the organisation's, never wider.** A product
may undertake to keep less than the organisation requires. It may not undertake
more, and it may not restate one of the organisation's undertakings in its own
words: an addition that redefined one is how a weaker promise arrives wearing a
stronger promise's name, and a reader comparing the two would find them agreeing
on the identifier and disagreeing on the meaning.

Every undertaking carries three things — an identifier, the sentence, and how a
reader establishes it for themselves. The third is required. An undertaking
nobody can check is a request to be trusted, and a request to be trusted is the
thing this organisation is trying not to make. It would also be the most
comfortable entry to add and the only worthless one.

## What holds it together

Three tests, in `internal/promises` and `internal/web`:

| | |
|---|---|
| `TestEveryUndertakingCanBeCheckedAndIsNamed` | every entry has a stable identifier, says something, and says how to check it; no identifier is used twice |
| `TestNoProductRedefinesWhatTheOrganisationUndertakes` | no product addition carries an organisation identifier, and every addition is named for the product it belongs to |
| `TestTheUndertakingsAreNotCopiedIntoAnyPage` | nothing served to a visitor carries these sentences in its own words; the pages range over the one place they live |
| `TestThePageAboutTheOrganisationCarriesEveryUndertaking` | the rendered page carries every undertaking and every way of checking one, each addressable by its identifier |
| `TestThePrivacyPageSendsAReaderToTheOrganisation` | a reader who arrived with the other question is pointed across, above the jump list rather than below it |

The last one exists because a split nobody is pointed across is a page that was
hidden rather than separated. The footer here is deliberately three links long —
it carried six once and nobody read them — so the pointer lives in the prose at
the top of each privacy page, where the question comes up.

## A second product

Everything above is written so that the second product costs nothing. What it
has to do:

1. **Carry the organisation's list unchanged**, from one place, and render it
   rather than retyping it. If the second product is a separate repository, that
   repository holds its own copy of the list *as data*, and the two copies must
   be identical — which nothing can check across repositories, so the canonical
   text is the one served at `https://denyfirst.dev/organisation` and a
   difference from it is a fault in the copy.
2. **Add its own restrictions underneath**, each with an identifier prefixed by
   the product's name, each narrower than an organisation undertaking, none
   restating one.
3. **Say how each is checked.** Not "we do not log" but where the absence of
   logging can be seen.
4. **Point across.** Its privacy page says where the organisation's undertakings
   are, above the jump list.

And one thing it must not do: add an undertaking to the organisation's list
because it happens to be true of that product. The organisation's list grows
only when the organisation's conduct changes, and then it grows for every
product at once — which is the whole point of it being one list.

## Where the pages are

| | |
|---|---|
| `/organisation` | what denyfirst undertakes, and what each product adds |
| `/privacy` | what this service keeps, what a scan does, how to stop one |
| `/terms` | what you agree to, and what is not promised |
| `internal/promises` | the one place the undertakings are written |

The self-hosted build serves its own privacy page, describing that installation
from how it was started, and the same `/organisation` page: what the makers
receive is the same question wherever the copy runs, and the answer is the same
nothing.
