# Security invariants

Each rule below is something that must be true of Porch, where the code
enforces it, and the tests that fail if it stops being true. CI checks that
every test named here exists.

Two rules apply to every change:

- **Guard the action, not the entrance.** A check in an HTTP handler protects
  that handler. A check where the connection is opened protects every caller,
  including the ones not written yet.
- **Every guard gets a test that tries to defeat it.** Not a test that the
  happy path works: a test that the guard refuses.

The reasoning behind each rule, and how it came about, is in the comments of
the tests that guard it and in this file's history.

---

## Network

### N1 — Outbound connections refuse non-public addresses

*Enforced in:* `internal/safedial`, by default in `safedial.Dialer`

*Reached through:* `tlsprobe.Prober.dial`, which selects safedial when `Dial`
is nil

*Guarded by:* `TestCheckAddrBlocks`, `TestEmbeddedIPv4FormsAreBlocked`,
`TestSpecialPurposeBlockDoesNotReachDelegatedSpace`,
`TestDefaultDialerRefusesPrivateTargets`,
`TestZeroScannerRefusesPrivateTargets`, `TestPrivateTargetsAreRefused`

### N2 — The HTTP service cannot be configured to reach private addresses

*Enforced by:* the absence of any option in `internal/httpapi`

*Guarded by:* `TestPrivateTargetsAreRefused`

### N3 — Only implicit-TLS ports are dialled

*Enforced in:* `internal/scan`, in `Scanner.Scan`, unless `AllowAnyPort`;
`internal/scan.Scanner.prober`, passed to `internal/safedial.Dialer`

*Lifted by:* the command line only

*Guarded by:* `TestScannerEnforcesPortsByDefault`, `TestCheckPort`,
`TestAllowedPortsAreImplicitTLS`, `TestThePortAllowListReachesTheDialer`,
`TestTheAllowListReachesTheDialer`,
`TestTheDefaultDiallerReachesOnlyPort25OnPublicAddresses`,
`TestOnlyTheExchangersTheDomainNamesAreAsked`,
`TestTheServiceAsksExchangersOnlyWhereItRequiredProof`,
`TestTheRelayQuestionIsBoundedAndOnlyAskedWhenWanted`,
`TestAnExchangerThatAcceptsTheRecipientIsReported`,
`TestWhatTheRelayQuestionCouldNotEstablishIsSaidAsThat`,
`TestTheRelayQuestionGoesOnlyToTheDomainsOwnExchangers`,
`TestAnExchangerBehindAnAliasIsNotAskedAboutRelay`,
`TestAnOpenRelayIsGradedAndSilenceIsNot`,
`TestTheRelayQuestionIsAskedOverEncryptionWhereThereIsOne`,
`TestTheRelayAnswerReachesBothFacesOfTheReport`

### N4 — Every network operation is bounded

*Enforced in:* `internal/safedial` (`Timeout`, `TotalTimeout`, `MaxAddrs`),
`internal/tlsprobe` (`HandshakeTimeout`, `TotalTimeout`), `internal/httpapi`
(`RequestTimeout`), `internal/rawhello.Ask` (the context's deadline on the
connection), `internal/rawhello.ReadReply` (at most the bytes an answer needs),
`internal/budget.ShortOf`, applied by `internal/scan` (the lookups after the
handshakes), `internal/mailscan.readExchangerTLS` and
`internal/webprobe.Prober.Probe`; `internal/smtptls.Prober.dialer`

*Guarded by:* `TestCallerDeadlineWins`, `TestTotalTimeoutBoundsTheOperation`,
`TestAskStopsWhenTheContextDoes`, `TestNoMoreIsReadThanTheAnswerNeeds`,
`TestAskStopsWhenTheContextIsCancelledWithoutADeadline`,
`TestASilentExchangerIsBounded`, `TestAnEnormousLineIsNotReadToItsEnd`,
`TestAReplyThatNeverEndsIsBounded`,
`TestARecordFromAnotherProtocolVersionIsNotBelieved`,
`TestAnOversizedRecordIsNotBelievedWhateverFollows`,
`TestOnlyAServerHelloIsAnAcceptance`,
`TestAServerHelloSplitAcrossRecordsIsNotGuessed`, `FuzzReadReply`,
`TestASlowLogSearchDoesNotCostTheReport`,
`TestExchangersThatNeverAnswerDoNotCostTheReport`,
`TestOpeningAConnectionIsBoundedApartFromTheConversation`,
`TestNothingIsAskedAfterTheExchangers`,
`TestAMeasurementAfterTheChainsDoesNotCostTheReport`,
`TestTheQuestionsAfterAMeasurementEndShortOfTheDeadline`,
`TestAMonitorThatNeverAnswersDoesNotCostTheRecords`,
`TestAThirdPartyAskedFirstLeavesHalfTheTime`

### N6 — The public deployment connects only to hosts this project owns

*Enforced in:* `internal/demo` (`demo.go`, `demo_on.go`, `demo_off.go`),
`internal/scan.Scanner.Scan`, `internal/webscan.Scanner.Scan`,
`internal/httpapi.Server.handleScan`, `internal/httpapi` (`check`, `target`),
`internal/web/assets/index.html`, `scripts/build.sh`, `docs/releasing.md`

*Guarded by:* `TestTheOrdinaryBuildIsNotADemonstration`,
`TestTheWebScannerRefusesAHostThisProjectDoesNotOwn`,
`TestARefusedHostIsNeverConnectedTo`,
`TestTheOrdinaryWebScannerIsNotADemonstration`, `TestTheWebRefusalNamesNoHost`,
`TestAMistypedTargetIsToldItIsMistyped`,
`TestEveryHostOfferedIsOneThisScannerWillReach`,
`TestTheTagSwitchesTheWebScannerToo`,
`TestTheDemonstrationListMatchesAtLabelBoundaries`,
`TestABlankEntryAdmitsNothing`, `TestTheBuildTagTouchesNothingElse`,
`TestTheDemonstrationBuildRefusesAHostItDoesNotOwn`,
`TestTheDemonstrationRefusalNamesNoHost`, `TestTheDemonstrationListIsNotEmpty`,
`TestTheTagIsWhatSwitchesIt`, `TestEveryHostOfferedIsOneTheScannerWillReach`,
`TestTheDemonstrationPageOffersWhatItCanScan`,
`TestTheDemonstrationPageSaysWhatItIsAndWhereTheToolIs`,
`TestTheDemonstrationRefusalIsAnsweredAndCounted`,
`TestEveryRefusalCodeCanBeProduced`,
`TestTheWebEndpointWalksTheSameChainOfGuards`,
`TestTheWebEndpointRefusesAPortRatherThanDroppingIt`,
`TestOneScanAllowanceCoversBothChecks`,
`TestTheTargetBudgetIsSharedBetweenTheChecks`,
`TestAnAddressIsRefusedTheSameWayOnBothEndpoints`,
`TestTheHandlerNeverAcceptsATargetTheProbeWouldRefuse`,
`TestTheWebTargetIsFoldedBeforeAnythingSeesIt`,
`TestTheWebEndpointDoesNotAnswerAGet`,
`TestAVersionSaysWhichHostsTheBinaryWillReach`,
`TestTheVersionOutputCarriesTheReachLine`,
`TestTheDemonstrationBuildIsReleasedAndDeployed`

### N7 — An HTTP request is one GET of the root, and no path is ever invented

One `GET` of `/` over HTTPS and over plaintext; after that, only the addresses
a `Location` header names. The only other paths ever asked for are files that
exist to be read by strangers: `/.well-known/security.txt`,
`/.well-known/mta-sts.txt` where a zone announces a policy, and
`/.well-known/porch-challenge` for proof of control.

*Enforced in:* `internal/webprobe`, `internal/markup`,
`internal/webprobe.Prober.pageFacts`, `internal/webscan.Scanner.Scan`,
`internal/httpapi.Server.operatorView`

*Guarded by:* `TestTheAddressesAreKeptOnlyWhereTheCallerAsked`,
`TestTheCommandLinePrintsTheSecurityContacts`,
`TestTheServicePrintsSecurityContactsOnlyWhereItRequiredProof`,
`TestTheContactsKeptAreBoundedAndTheCountIsNot`,
`TestAContactIsCleanedBeforeItIsKept`,
`TestTheRevocationAddressesAreKeptOnlyWhereAskedFor`,
`TestTheCommandLineNamesTheRevocationAddresses`,
`TestTheRevocationAddressesFollowTheOperatorsView`,
`TestTheOperatorsOwnCopyShowsTheWholeReport`,
`TestWhereRevocationIsCheckedIsNamedWhenItIsKnown`,
`TestARevocationAddressIsCleanedBeforeItIsKept`,
`TestTheOtherFormIsAskedEvenWhereTheNameItselfIsDead`,
`TestTheOtherFormIsAskedOnceAndNotFollowed`,
`TestTheOtherFormOfANameIsDerivedAndNotSearchedFor`,
`TestTheOtherFormGoesThroughWhateverDecidesWhatMayBeReached`,
`TestTheOtherFormOfTheNameRowSaysHowTheTwoAgree`,
`TestWhereThisNameLandsReachesTheRowAboutTheOtherForm`,
`TestWhichPublishedAddressesCanBeTried`,
`TestWhatAnIPv6HandshakeSaysAboutTheCertificate`,
`TestTheIPv6RowSaysWhichKindOfNoItFound`,
`TestWhoAFailedIPv6ConnectionIsAboutDependsOnThisMachine`,
`TestWhatCountsAsThisMachineHavingIPv6`,
`TestTheIPv6MeasurementRunsOnAScanAndReachesTheReport`,
`TestAScanThatRanOutOfTimeSaysSoRatherThanBlamingTheHost`,
`TestADeadlineDuringTheIPv6HandshakeIsNotTheLocalNetworksFault`,
`TestTheOtherFormSaysTheScanRanOutWhenTheDeadlinePassesMidRequest`,
`TestTheSecurityContactSaysTheScanRanOutRatherThanThatTheFileIsMissing`,
`TestNothingIsLookedUpOrDialledWithNoTimeLeft`,
`TestTheReachDecisionIsNotAskedWithNoTimeLeft`,
`TestWhatIsReadIsCountedAndNotKept`, `TestASignatureIsNotReadAsFields`,
`TestTheThreeKindsOfNothing`,
`TestTheSecurityContactRowSaysWhichNothingItFound`,
`TestEveryWellKnownAddressInTheSourceIsNamedHere`,
`TestTheListAndTheWrittenPromiseAgree`,
`TestCoversRefusesAnAddressNobodyDecidedOn`,
`TestOnlyTheRootIsRequestedUnlessTheServerSaysOtherwise`,
`TestARedirectChainIsRecordedInOrder`,
`TestTheRedirectLimitStopsTheChainAndSaysSo`,
`TestARelativeLocationIsResolvedAgainstTheAddressThatSentIt`,
`TestALocationWithAnotherSchemeIsNotFollowed`,
`TestALocationCarryingCredentialsIsStrippedBeforeItIsFollowed`,
`TestARedirectsTokenIsFollowedAndNotKept`, `TestRedactAddress`,
`TestAnOverlongLocationIsNotFollowed`, `TestOnlyTheGradedHeadersAreRecorded`,
`TestACookieValueIsNeverRecorded`, `TestCookieAttributesAreRead`,
`TestTheScopeAttributesAreRead`,
`TestTheScopeAttributesDidNotAddSomewhereForAValue`,
`TestTheRecommendedHeadersAreReportedAndNotGraded`,
`TestTheBodyIsNotReadByDefault`, `TestTheBodyIsNotReadUnlessItIsAskedFor`,
`TestThePageIsReadWhenItIsAskedFor`, `TestSomethingThatIsNotAPageIsNotRead`,
`TestTheMediaTypeIsReadWithoutItsParameters`, `TestARedirectsBodyIsNotRead`,
`TestAThreeHundredWithNowhereToGoIsAPage`, `TestALongPageIsBoundedAndSaysSo`,
`TestTheDemonstrationShowsItsOwnEstateWhole`,
`TestTheScannerDecidesWhetherThePageIsRead`, `TestNoMarkupReachesTheResult`,
`TestNothingButTheHostSurvives`, `TestOnlyAnExplicitPlaintextAddressCounts`,
`TestACommentedOutReferenceIsNotOne`, `TestWhatIsInsideAScriptIsNotMarkup`,
`TestAClosingTagInCapitalsStillCloses`, `TestALongPageIsTruncatedAndSaysSo`,
`TestTheZeroValueIsNotACleanPage`,
`TestAPageLoadingItsOwnThingsRecordsNothing`, `TestAnotherOriginIsRecorded`,
`TestASiblingSubdomainIsAnotherOrigin`, `TestThePagesOwnHostIsFolded`,
`TestWithNoHostNothingIsThirdParty`, `TestIntegrityIsReadWhereABrowserReadsIt`,
`TestAnEmptyIntegrityIsNotIntegrity`,
`TestIntegrityIsNotRecordedWhereItDoesNothing`,
`TestASchemeRelativeAddressIsReadAsThePagesOwnScheme`,
`TestNothingOverTLSIsBlocked`,
`TestAReferenceCanBeBothPlaintextAndAnotherOrigin`,
`TestAnAddressIsReadAsABrowserResolvesIt`,
`TestABaseElementMovesRelativeAddresses`,
`TestAnEmptyAddressIsNotABaseReference`, `TestAnotherPortIsAnotherOrigin`,
`TestEveryAddressInASrcsetIsRead`, `TestAFormActionOnAControlIsAFormAction`,
`TestAStylesheetAmongOtherRelationsIsAStylesheet`,
`TestAReadThatFailsPartWayIsWhatWasSeen`,
`TestAnIncompleteReadSaysWhatItCouldNotSee`,
`TestAnIncompletePageReachesTheGrading`,
`TestWhatThePagePullsInFromElsewhereReachesTheReport`,
`TestAPageLoadingItsOwnThingsIsToldNothing`,
`TestPlaintextIsAnsweredBeforeIntegrity`,
`TestTheUserAgentIdentifiesTheToolAndWhereToReadAboutIt`,
`TestAnEmptyUserAgentIsNotAvailable`, `TestABareHostnameIsRequired`,
`TestTheDefaultDiallerRefusesPrivateAddresses`,
`TestTheDefaultDiallerRefusesPortsOtherThanEightyAndFourFourThree`,
`TestTheClientFollowsNothingByItself`,
`TestNoProxyStandsBetweenThisAndTheHost`, `TestTheTwoChainsAreIndependent`,
`TestEveryAddressThisProjectSendsOutResolves`

### N8 — Some names are refused before anything connects to them

*Enforced in:* `internal/exclusion`, `internal/scan.Scanner.Scan`,
`internal/webscan.Scanner.Scan`, `internal/httpapi.Server.handleScan`

*Guarded by:* `TestExcludedNamesAreRefused`,
`TestExclusionMatchesAtLabelBoundaries`,
`TestOrdinaryGovernmentSitesAreNotExcluded`,
`TestExclusionIgnoresCaseAndTrailingDot`, `TestOperatorCanAddNames`,
`TestScannerRefusesExcludedNames`, `TestTheWebScannerRefusesAnExcludedName`,
`TestTheWebExclusionRefusalNamesNoHost`,
`TestTheWebScannerScansANameThatIsNotExcluded`,
`TestTheExclusionListIsNotOverriddenByTheDeploymentList`,
`TestEveryRefusalCodeCanBeProduced`

### N9 — A deployment scans only estates it has been shown control of

*Enforced in:* `internal/verify`, `internal/challenge`,
`internal/scan.Scanner.Scan`, `internal/webscan.Scanner.Scan`,
`internal/httpapi.New`, `internal/httpapi.Server.UseWebScanner`,
`internal/httpapi.Server.handleVerify`, `internal/httpapi.Server.operatorView`,
`internal/web.Installation.Whole`, `cmd/porchd.verificationScope`

*Guarded by:* `TestTheChallengeIsReadFromTheZonesOwnServersAndNoResolver`,
`TestGlueFromOutsideItsZoneIsNotBelieved`,
`TestAnAliasIsWalkedFromTheRootAndNotBelieved`,
`TestAWalkThatNeverEndsIsBounded`,
`TestTheZonesOwnServersDecideAndNotAResolver`,
`TestTheServiceReadsTheChallengeFromTheZone`,
`TestTheFlagsThatOpenedAServiceAreRefused`, `TestNoServiceFlagTurnsProofOff`,
`TestNoCommandLineFlagTurnsProofOff`, `TestNoGuideDownloadsAWithdrawnBinary`,
`TestTheSecurityPolicySaysWhichVersionsAreSupported`,
`TestEveryTargetIsProvenBeforeAnythingIsChecked`,
`TestTheCommandLineKeepsItsOwnSecretAndAsksNoResolver`,
`TestTheCommandLineProvesBeforeItChoosesACheck`,
`TestAProofThatCouldNotBeReadIsNotAPass`,
`TestOnlyTheWebCheckAcceptsTheServedFile`,
`TestOneRecordCoversTheServiceAndTheCommandLine`,
`TestTheCommandLineOnTheServerUsesTheServicesSecretAndChangesNothing`,
`TestAServerHoldsTheReleaseAndNothingElse`,
`TestEveryCheckAsksForProofWhereItConnects`, `TestARunAsksTheZoneOncePerName`,
`TestAnAddressIsNotCheckedFromTheCommandLine`,
`TestTheOperatorsOwnCopyShowsTheWholeReport`,
`TestTheOperatorsOwnCopySaysItShowsTheWholeReport`,
`TestAPublishedTokenCoversTheZone`, `TestADomainThatProvedNothingIsRefused`,
`TestATokenFromOneDomainDoesNotProveAnother`,
`TestATokenFromAnotherDeploymentIsNotAccepted`,
`TestTheTokenIsFoundAmongOtherRecords`, `TestAScopeThatCannotCheckRefuses`,
`TestALookupFailureIsNotAnUnverifiedDomain`, `TestTheRefusalNamesNoHost`,
`TestTheWalkDoesNotReachForAPublicSuffix`,
`TestTheMostSpecificNameIsAskedFirst`, `TestATokenIsStableAndSpellable`,
`TestTheTLSScannerRefusesAnUnverifiedNameBeforeDialling`,
`TestTheTLSScannerScansAVerifiedName`,
`TestTheTLSScannerNeedsNoProofByDefault`,
`TestAnUnverifiedNameIsRefusedBeforeAnythingIsDialled`,
`TestAVerifiedNameIsScanned`, `TestNoScopeMeansNoProofIsRequired`,
`TestAnExcludedNameIsRefusedAsExcludedRatherThanAsUnproven`,
`TestEveryScanningEndpointRequiresProofOfControl`,
`TestTheVerifyEndpointNamesTheRecordAndSaysWhetherItIsThere`,
`TestTheVerifyEndpointReadsWhatTheChecksRead`,
`TestAnOpenDeploymentHasNothingToVerify`,
`TestAFailedChallengeLookupIsNotUnverified`,
`TestTheVerifyEndpointHasTheScanGuards`, `TestTheVerifyRecordsAreBounded`,
`TestProvingDomainsDoesNotSpendTheScanAllowance`,
`TestSignedProofIsReportedAndCanBeRequired`,
`TestTheVerifyEndpointSaysWhetherTheProofWasSigned`,
`TestSignedProofOnlyNeedsProofAndReachesTheScope`,
`TestDomainsSaysWhetherTheProofWasSigned`,
`TestProofLookupsInFlightAreBounded`, `TestTheProofDefaultsToTheNameItself`,
`TestAMissingSecretIsCreatedAndThenKept`,
`TestTheSecretIsCreatedByStartingAndNotByAsking`,
`TestAServiceWithoutProofDoesNotStart`,
`TestTheComposeFileTakesAwayWhatItSays`,
`TestTheProofDialogIsOfferedOnlyWhereProofIsRequired`,
`TestTheConsoleAsksForProofBeforeItRuns`,
`TestOnlyTheEndpointsThatOpenNothingAskWithoutScanning`,
`TestAServedFileIsNotReportedAsProofForEveryCheck`,
`TestAnUnprovenNameOpensTheDialog`, `TestAProvenDomainReachesTheProbe`,
`TestTheConstructorGivesEveryCheckTheSameBoundary`,
`TestReplacingTheWebScannerCannotDropTheBoundary`,
`TestTheVerificationRefusalStatesTheRuleWithoutRepeatingTheTarget`,
`TestALookupFailureIsNotAnsweredAsUnproven`, `TestAServedFileProvesTheHost`,
`TestAServedFileProvesNoOtherName`,
`TestAServedFileDoesNotProveACheckThatLeavesTheBrowsersPorts`,
`TestTheZoneProofCoversEverySurface`, `TestAFileWithTheWrongTokenIsRefused`,
`TestAFailedFetchIsNotAHostThatPublishedNothing`,
`TestAHostServingNoFileIsRefusedRatherThanErrored`,
`TestNoFetcherMeansOnlyTheZoneProofWorks`,
`TestAHostWithAZoneProofIsNeverFetchedFrom`,
`TestOnlyTheChallengePathIsRequested`,
`TestAMissingFileIsNoChallengeRatherThanAnError`,
`TestAnEmptyFileIsNoChallenge`, `TestARedirectIsNotFollowed`,
`TestAFetchFailureNamesNoInfrastructure`,
`TestTheDefaultDiallerRefusesPrivateAddresses`,
`TestAChallengeIsNotReadOverAnUntrustedConnection`,
`TestAFileProofDoesNotOpenTheTLSCheck`, `TestAFileProofOpensTheWebCheck`,
`TestAFileProofDoesNotOpenAnotherName`

### N10 — A redirect is a connection the scanned server chose

*Enforced in:* `internal/webprobe.Prober.chain`, `internal/webprobe.walk`,
`internal/webscan.Scanner.reachable`

*Guarded by:* `TestARedirectIsNotFollowedToAHostTheCallerRefuses`,
`TestARedirectIsFollowedToAHostTheCallerAllows`, `TestANilReachFollowsAnyHost`,
`TestTheHostAskedAboutIsNotAskedAgain`, `TestOneQuestionPerDistinctHost`,
`TestTheHostIsFoldedBeforeTheBoundaryIsAsked`,
`TestARefusedRedirectIsNotReportedAsTheRedirectLimit`,
`TestARedirectToAnExcludedDomainIsNotFollowed`,
`TestARedirectOutOfTheVerifiedZoneIsNotFollowed`,
`TestARedirectInsideTheVerifiedZoneIsFollowed`,
`TestARedirectIsNotFollowedWhenTheBoundaryCannotBeAsked`,
`TestTheRedirectRefusalNamesNoHost`,
`TestARedirectOffTheDemonstrationIsNotFollowed`,
`TestARedirectInsideTheDemonstrationIsFollowed`

### N11 — An address a certificate names is an address the scanned party chose

*Enforced in:* `internal/crl`, `internal/scan.Scanner.Scan`,
`internal/scan.listStatus`, `internal/policy.GradeStapling`,
`internal/policy.RevocationLine`

*Guarded by:* `TestAReportThatAskedTheResponderDoesNotSayNobodyDid`,
`TestACertificateOnTheListIsRevoked`, `TestACertificateNotOnTheListIsGood`,
`TestAListTheIssuerDidNotSignIsRefused`,
`TestAListThatDoesNotCoverTheCertificateIsNotAnAnswer`,
`TestAListScopedToThisCertificateStillAnswers`,
`TestARealIssuingDistributionPointIsRead`, `TestAStaleListIsNotAnAnswer`,
`TestAListNotYetInEffectIsNotAnAnswer`,
`TestAnOversizedListIsRefusedRatherThanTruncated`,
`TestASerialIsComparedAsANumber`, `TestOnlyHTTPAddressesAreFetched`,
`TestCredentialsInADistributionPointAreStripped`,
`TestACertificateNamingNoListSaysSo`, `TestWithoutTheIssuerThereIsNoAnswer`,
`TestAListThatWasNotServedEstablishesNothing`,
`TestSomethingThatIsNotAListIsNotParsedAsOne`,
`TestNoReasonDescribesTheMachine`,
`TestTheDefaultDiallerRefusesPrivateAddresses`,
`TestAnUnknownListStatusIsNotAnAnswer`,
`TestTheOrdinaryBuildReadsTheRevocationList`,
`TestTheDemonstrationReadsItsOwnRevocationList`,
`TestTheRevocationLimitDescribesThisBuild`,
`TestAListThatNamesTheCertificateIsReported`,
`TestAListThatDoesNotNameTheCertificateSaysAsOfWhen`,
`TestAListThatCouldNotBeReadSaysWhy`, `TestOneWithdrawalIsOneFinding`,
`TestADeploymentThatReadsNoListIsUnchanged`

### N12 — A question that names the domain is a disclosure, and is treated as one

*Enforced in:* `cmd/porch-scan.httpsEndpoint`, `cmd/porchd.httpsEndpoint`,
`internal/policy.UnaccountedLine`, `internal/scan.Scanner.searchLogs`,
`internal/ctsearch`, `internal/ctsearch.SearchEstate`, `internal/liveness`,
`internal/liveness.Checker.one`, `internal/dnsclient.withPort`,
`internal/dnsnames`, `internal/dnsnames.Reader.Under`, `internal/inventory`,
`internal/inventory.Merge`, `internal/inventory.Inventory.Hosts`,
`cmd/porch-scan.printNamesNow`, `cmd/porch-scan.saysLogs`,
`cmd/porch-scan.saysRecords`, `internal/httpapi.handleNames`,
`internal/httpapi.Server.inventory`, `internal/httpapi.keptInventories`,
`internal/httpapi.Server.records`, `internal/httpapi.Server.live`,
`internal/inventory.Inventory.WithLiveness`, `internal/inventory.Sources`,
`internal/passivedns`, `internal/passivedns.SecurityTrails.Under`,
`internal/passivedns.VirusTotal.Under`, `internal/certnames`,
`internal/certnames.Reader.Under`, `internal/liveness.Answering`,
`internal/ptrnames`, `internal/ptrnames.Reader.Under`,
`internal/ptrnames.Addresses`, `internal/httpapi.Server.operatorOnly`,
`internal/httpapi.parseRanges`, `internal/inventory.Name.MarshalJSON`,
`internal/inventory.Inventory.MarshalJSON`, `internal/ptrnames.Reverse`,
`internal/dnsclient.Client.LookupPTR`, `cmd/porch-scan.rangesNamed`,
`internal/inventory.Inventory.Unasked`, `internal/httpapi.Server.presented`,
`internal/passivedns.looksLikeAName`, `cmd/porch-scan.registerNamed`,
`cmd/porchd.namesRegister`, `internal/ctsearch.under`,
`internal/scan.Scanner.searchLogs`, `internal/scan.sameSerial`,
`internal/policy.LoggedLine`, `internal/policy.DescribeLogged`,
`cmd/porch-scan.tlsScanner`, `internal/zonenames`,
`internal/zonenames.Reader.Under`, `internal/zonenames.Found.keep`,
`internal/dnsclient.Client.Transfer`, `internal/dnsclient.transferNames`,
`internal/dnsclient.readTransferMessage`,
`internal/httpapi.Server.ReadZoneTransfers`, `internal/httpapi.zoneReader`,
`cmd/porch-scan.saysZone`, `internal/nsecnames`,
`internal/nsecnames.Reader.Under`, `internal/dnsclient.Client.LookupNSEC`,
`internal/inventory.FromNSEC`, `internal/httpapi.Server.WalkAbsenceProofs`,
`internal/httpapi.absenceWalker`, `cmd/porch-scan.saysNsec`,
`internal/knownnames`, `internal/knownnames.From`,
`internal/knownnames.ReadFile`, `internal/knownnames.MaxNames`,
`internal/inventory.FromOperator`, `cmd/porch-scan.namesGiven`,
`cmd/porch-scan.saysKnown`, `cmd/porch-scan.onlyGiven`,
`internal/httpapi.DefaultMaxInventoryBytes`,
`internal/inventory.Inventory.Readings`,
`internal/inventory.Inventory.Failures`, `internal/web.consoleChecks`,
`internal/web.consoleCheck`, `internal/policy.Informational`,
`cmd/porch-scan.shortInventory`, `cmd/porch-scan.runNames`,
`cmd/porch-scan.printNamesLimits`

*Guarded by:* `TestTheDemonstrationListsItsOwnEstate`,
`TestTheDemonstrationKeepsTheInventoryItProduced`,
`TestTheDemonstrationIsWiredToListItsOwnEstate`,
`TestAKeptInventoryIsProducedAgainWhenItAgesOut`, `TestAFailedSearchIsNotKept`,
`TestTheHostsCertificatesAloneDoNotEstablishAnInventory`,
`TestAnInventoryOnlyTheEmptyHostListAnsweredIsNotKept`,
`TestVisitorsArrivingTogetherAskOneQuestion`,
`TestKeepingNothingProducesAnInventoryForEveryCaller`,
`TestEveryPageOfAPagedAnswerIsRead`, `TestAnEstatePastTheBoundSaysItWasCut`,
`TestOneCertificateUnderTwoIdentifiersIsOne`, `TestEachStateIsItsOwnAnswer`,
`TestNothingPrivateIsEverDialled`, `TestAnEstatePastTheBoundIsCut`,
`TestWhatEachNameIsDoingIsTheFirstThingOnTheLine`,
`TestNamesSurviveAReportThatEstablishedNoStatus`,
`TestAWildcardIsNeverAskedAboutAsAName`,
`TestAResolverAddressWorksWithoutAPort`,
`TestANameSaysWhatItIsDoingAndWhenItWasLastCovered`,
`TestRateLimitingIsSaidPlainly`,
`TestTheKeyIsSentAsACredentialAndNotWrittenDown`,
`TestWhatCountsAsReachableByAnybodyElse`,
`TestAnInstallationNobodyElseCanReachNeedsNoProof`,
`TestVerificationConfiguredIsEnforcedEvenOnLoopback`,
`TestTheMonitorIsNotDescribedToSomebodyWhoProvedNothing`,
`TestAnInventoryIsOnlyProducedForAProvenDomain`,
`TestAnInstallationWithNoVerificationProducesNoInventory`,
`TestTheDemonstrationInventoriesNoEstate`,
`TestNeitherSourceIsReadForAnUnprovenDomain`,
`TestTheZoneIsReadOnlyForAProvenDomain`,
`TestAnInstallationNotToldToReadAZoneDoesNot`,
`TestATransferThatStopsPartWayThroughSaysItWasCut`,
`TestAZoneIsReadFromTheServerThatHandsItOver`,
`TestATransferRecordCannotReachPastItsMessage`,
`TestAServerThatRefusesATransferIsNotAFailure`,
`TestEveryServerRefusingIsNotAFailure`,
`TestADelegationThatCannotBeReadIsNotARefusal`,
`TestTheReportSaysWhatTheZoneHandedOver`, `TestTheZoneHandsOverItsOwnList`,
`TestWhatAServerSendsIsCleanedBeforeItIsKept`,
`TestWhatAZoneHandedOverIsItsOwnSource`,
`TestAnAddressRangeIsWalkedForTheOperatorAndNobodyElse`,
`TestACheckRefusesAddressRanges`, `TestARangeTooWideIsRefusedByTheService`,
`TestARangeTooWideToWalkIsRefused`, `TestTheRangesAreReadAndRefusedEarly`,
`TestWhatAReverseRecordSaysIsCleanedBeforeItIsKept`,
`TestWhatTheAddressesAnswerTo`,
`TestAResolverThatAnsweredNothingIsNotAnEmptyRange`,
`TestNamingNoRangeAsksNothing`, `TestTheReportSaysWhatTheAddressesAnsweredTo`,
`TestTheReverseNameIsTheOneAResolverAnswers`,
`TestTheNameAnAddressAnswersToIsRead`,
`TestANameWithNoDateCarriesNoneInTheJSON`, `TestEveryInstallationHasAResolver`,
`TestEveryInstallationIsWiredAResolver`,
`TestNoServedPageLeaksATemplateAction`,
`TestWhatAnAddressAnsweredToIsItsOwnSource`,
`TestNoCertificateIsReadForAnUnprovenDomain`,
`TestNothingIsSentToAHostAfterTheHandshake`,
`TestAnsweringAreTheNamesSomethingIsListeningOn`,
`TestACertificateNobodyTrustsIsStillRead`,
`TestUnaskedAreTheNamesNothingHasAskedAboutYet`,
`TestTheServiceReadsTheCertificatesTheHostsPresent`,
`TestWhatAHostPresentedIsItsOwnSource`, `TestAReportThatAskedNoHostSaysSo`,
`TestTheReportSaysWhatTheHostsPresented`, `TestTheNamesAHostPresents`,
`TestAHostThatDoesNotAnswerIsCountedAndNotInvented`,
`TestAskingNoHostsIsNotAFailure`,
`TestANameFromACertificateBelongsToTheEstateOnlyOnALabelBoundary`,
`TestWhatAHostSaysIsCleanedBeforeItIsKept`,
`TestNoRegisterIsBuiltUntilOneIsNamedWithAKey`,
`TestWhatARegisterSaysIsCleanedBeforeItIsKept`,
`TestANameFromARegisterBelongsToTheEstateOnlyOnALabelBoundary`,
`TestEveryPageOfARegistersAnswerIsRead`,
`TestACursorThatDoesNotMoveEndsTheWalk`,
`TestAnEstatePastTheRegistersPageBoundSaysItWasCut`,
`TestARegisterIsNotFollowedToAnotherAddress`,
`TestWhatARegisterRefusedIsSaidPlainly`,
`TestNothingHeldIsNotTheSameAsNothingEstablished`,
`TestAWildcardWithNoRegisterSaysNothingLookedBehindIt`,
`TestTheReportSaysWhatARegisterObserved`,
`TestTheServiceReadsTheRegisterOnlyForAProvenDomain`,
`TestAnInstallationWithNoRegisterSaysItAskedNone`,
`TestARegisterThatWasNeverAskedIsNotAnEmptyRegister`,
`TestWhatARegisterObservedIsItsOwnSource`,
`TestARegisterThatWasCutSaysSoInTheInventory`,
`TestWhatARegisterHasSeenUnderADomain`,
`TestNoNameIsProbedForAnUnprovenDomain`,
`TestTheProbeTheServiceBuildsRefusesPrivateDestinations`,
`TestANameNothingReachedIsStillInTheReport`,
`TestWhatEachNameIsDoingGoesBesideTheName`,
`TestAnEstateWhereNothingAnswersWasStillAsked`,
`TestAnInstallationWithNoResolverSaysTheRecordsWereNotRead`,
`TestTheServiceReadsBothSourcesForAProvenDomain`,
`TestBothFacesSayTheSameThingAboutWhatTheInventoryMisses`,
`TestEveryNameSaysWhatNamedIt`, `TestTwoSpellingsOfOneHostAreOneHost`,
`TestOneHostNamedTwiceIsOneName`, `TestTheWindowSurvivesTheMerge`,
`TestASourceThatFailedIsNotAnEmptyEstate`,
`TestAnInventoryMissingASourceSaysWhichOne`,
`TestARecordSourceWithNoShortLabelIsStillCarried`,
`TestEverySourceIsAReadingAndEveryReadingIsListed`,
`TestThePageDrawsALineForEverySourceTheInventorySends`,
`TestThePageReadsTheNameFieldsTheAPISends`,
`TestAWalkOfTheAbsenceProofsIsItsOwnSource`,
`TestTheReportSaysWhatTheProofsListed`,
`TestTheAbsenceProofsAreWalkedOnlyForAProvenDomain`,
`TestAnInstallationNotToldToWalkProofsDoesNot`,
`TestAZoneWithNoPlainProofsSaysSo`, `TestASignedZoneListsItself`,
`TestAChainThatDoesNotComeRoundIsCut`, `TestAChainThatLeavesTheDomainStops`,
`TestAZoneThatNeverComesRoundIsStopped`,
`TestTheListIsTakenAsGivenAndHeldToTheDomain`,
`TestAFileIsOneNameToALineWithRoomForNotes`,
`TestAListSomebodyGaveIsItsOwnSource`, `TestAListLongerThanAnEstateIsRefused`,
`TestAListLongerThanAnEstateIsRefusedByTheService`,
`TestAListOfNamesIsReadForAProvenDomainAndNoOther`,
`TestACheckRefusesAListOfNames`,
`TestTheConsoleOffersTheInventoryAsADoorNotABox`,
`TestTheDemonstrationOffersTheInventoryAsADoor`,
`TestAMonitorOrRegisterIsAskedOnlyOverHTTPS`,
`TestTheCertificatesTheLoggedLineCountsAreListed`,
`TestTheCertificatesTheLoggedLineCountsArePrinted`,
`TestOneCertificateLoggedTwiceIsOneCertificate`,
`TestTwoDifferentCertificatesAreTwo`, `TestTheNameIsEscapedIntoTheQuery`,
`TestAwkwardNamesDoNotEscapeTheQuery`,
`TestNothingThatIsNotAnAnswerReadsAsNoneFound`,
`TestAnEmptyAnswerIsNotAFailure`, `TestWhatTheMonitorSaysIsBoundedAndStripped`,
`TestALongHistoryIsBoundedAndSaysSo`,
`TestAnOversizedAnswerIsRefusedRatherThanTruncated`,
`TestAnEmptyNameIsNotSearchedFor`,
`TestASerialFromAMonitorIsComparedAsANumber`,
`TestTheDemonstrationSearchesTheLogsForItsOwnName`,
`TestTheDemonstrationSearchesItsOwnNameAndKeepsItsReports`,
`TestAKeptReportIsScannedOnceAnIntervalAndSaysItsAge`,
`TestOnlyAnAnsweredReportIsKept`, `TestWithoutAnIntervalEveryCallerIsScanned`,
`TestTheOrdinaryBuildSearchesTheLogsWhenAsked`, `TestNoSearcherMeansNoSearch`,
`TestTheLogSearchIsOffUntilItIsAskedFor`,
`TestADeploymentThatSearchedNoLogsSaysNothing`,
`TestAFailedSearchIsNotAnEmptyEstate`, `TestOneCertificateInUseReadsAsSettled`,
`TestACertificateNotPresentedIsSaidPlainly`,
`TestWhatTheLogsHoldIsNeverGraded`,
`TestTheReportSaysSubdomainsWereNotSearched`,
`TestATruncatedListSaysSoAndKeepsItsCount`,
`TestANameBelongsToTheEstateOnlyOnALabelBoundary`,
`TestWhatTheInventoryKeepsAndWhatItCounts`,
`TestAnEmptyInventoryIsStillAnAnswer`,
`TestANameFromALogIsCleanedBeforeItIsKept`,
`TestTheSearchAsksForEverythingUnderTheDomainAndKeepsOnlyThat`,
`TestAMonitorThatWillNotAnswerIsNotAnEmptyEstate`,
`TestTheInventoryAlwaysSaysWhatItCannotShow`,
`TestAFailedSearchPrintsNoInventory`, `TestTheInventoryCountsInWords`,
`TestTheInventoryTakesADomainAndNotAnAddress`,
`TestTheSecondMonitorKeepsOnlyThisEstate`,
`TestAWildcardIsNeverAHostToResolve`, `TestWhatEachSourceDroppedIsKeptApart`,
`TestASourceThatFailedIsANonZeroExit`,
`TestAnInstallationWithAResolverReadsTheRecords`,
`TestTheServiceSaysWhatEachNameIsDoing`,
`TestAnAnswerIsMatchedToItsNameWhateverTheSpelling`,
`TestNoListIsNotAnEmptyList`, `TestAFileThatIsNotAListIsRefused`,
`TestAListIsNeverKeptForTheNextCaller`,
`TestTheReportSaysWhatTheListContributed`,
`TestTheNamesGivenComeFromTheFlagAndTheFile`,
`TestEveryFieldThePageOffersIsSent`, `TestAnInventoryIsNotOfAnAddress`

### N13 — A question about a zone is authorised by the zone, and asks nobody else

*Enforced in:* `internal/mailscan`, `internal/spf`, `internal/mtasts`,
`internal/policy.GradeMail`, `internal/policy.MailStandingLimits`,
`internal/httpapi.New`, `cmd/porch-scan.mailScanner`, `cmd/porch-scan.runMail`,
`internal/display.Mark`, `cmd/porch-scan.printRecord`

*Guarded by:* `TestOnlyTheMailCheckTakesSelectors`,
`TestTheMailCheckLooksUnderTheSelectorsTheCallerNamed`,
`TestTheSelectorFieldGoesOnlyToTheMailCheck`,
`TestANoteThatAsksForASelectorSaysWhereToFindOne`,
`TestAnExternalDestinationIsAskedWhetherItAgreed`,
`TestWhereTheReportsGoIsReadAndTheOutsideOnesAreAsked`,
`TestAResolverThatWillNotAnswerIsNotARefusal`, `TestOneVendorIsAskedOnce`,
`TestTheReportAddressesArePrintedOnlyWhenAskedFor`,
`TestTheAddressesCanBeDroppedWithoutTheFinding`,
`TestADestinationWithNoAddressStillNamesItsDomain`,
`TestWhereTheReportsGoReachesBothFacesOfTheReport`,
`TestTheTagIsReadAsThePlacesItNames`,
`TestATagNamingMoreThanAnybodyReadsIsBounded`,
`TestOnlyADMARCRecordIsAgreement`,
`TestTheRecordsReachTheirOwnerAndNobodyElse`,
`TestARecordCannotActOnTheDisplay`, `TestTheSPFLookupsThatFailAreNamed`,
`TestAWeakerSubdomainPolicyIsSaid`, `TestTheRecordsArePrintedUnderTheirRows`,
`TestTheVoidLookupFindingNamesThePolicies`, `TestNothingCanActOnTheDisplay`,
`TestAnExchangerThatIsAnAliasIsGraded`,
`TestAnAliasedExchangerReachesBothFacesOfTheReport`,
`TestTheAliasQuestionIsBoundedLikeTheExchangers`,
`TestTheScanAsksOnlyAboutTheDomainItWasGiven`,
`TestTheWalkStopsWhereAReceiverStops`,
`TestAPolicyUnderTheLimitIsWalkedInFull`,
`TestAnUnreadIncludeIsNotAVoidLookup`, `TestACancelledWalkAsksNothing`,
`TestTheTenthLookupIsFollowed`, `TestAnSPFCountThatIsALowerBoundIsSaidAsOne`,
`TestAnUnreadIncludeReachesTheReport`, `TestALowerBoundLookupCountIsSaidAsOne`,
`TestOnlyTheZoneProofAuthorisesAMailScan`,
`TestScanRefusesBeforeItAsksAnything`, `TestExclusionSurvivesTheSpelling`,
`TestScanTakesADomainAndNothingElse`, `TestScanReadsWhatTheZonePublishes`,
`TestAFailedLookupIsNotADomainWithNoPolicy`,
`TestTLSReportingIsOnlyTrueWhenTheRecordSaysSo`,
`TestOnlyARecordThatAnnouncesItselfIsDMARC`,
`TestTheDefaultPercentIsTheOneRFC7489Specifies`,
`TestAnEnormousTagDoesNotTravel`, `TestEveryReportCarriesTheMailLimit`,
`TestTheDurationIsMeasuredRatherThanAssumed`,
`TestAPolicyThatIncludesItselfStops`, `TestTheCountFollowsEveryInclude`,
`TestMoreThanTenLookupsIsOverTheLimit`, `TestTenLookupsIsNotOverTheLimit`,
`TestOnlyResolvingTermsAreCounted`,
`TestIncludesThatResolveToNothingAreCountedAsVoid`,
`TestARedirectIsCountedOnlyWhereItWouldBeFollowed`,
`TestTheIncludedDomainsAreListed`, `TestAnOverlongRecordIsBounded`,
`TestAResolverThatWillNotAnswerIsNotAMissingPolicy`,
`TestADomainThatDoesNotExistSaysSo`, `TestNoReasonDescribesTheMachine`,
`TestMailGradesWhatASpecificationCallsAnError`,
`TestMailDoesNotGradeADeliberatePosition`,
`TestTheLookupCountIsReportedBeforeItIsAFault`,
`TestOverTheLimitTheCountIsNotAlsoReportedAsFine`,
`TestNotReadIsDistinguishableFromNotPublished`,
`TestEveryMailReportCarriesTheStandingLimit`,
`TestTheMailLimitIsTheDeclaredOne`, `TestMailFindingsNameTheMailRuleSet`,
`TestTheMailExchangersAreRead`, `TestANullMXIsReadAsOne`,
`TestAHostileExchangerNameIsStripped`, `TestAnEnormousExchangerNameIsBounded`,
`TestTheNameRendererBoundsWhatItIsGiven`, `TestTheRootNameIsReadableAsItself`,
`TestADANERecordIsReadWithItsDataAndItsValidation`,
`TestTheAssociationDataIsCopiedOutOfTheReply`,
`TestAnEndEntityRecordMatchesTheLeafWhateverItsNameAndDates`,
`TestAnEndEntityRecordForAnotherKeyDoesNotMatch`,
`TestATrustAnchorRecordNeedsTheLeafToChainAndNameTheExchanger`,
`TestATrustAnchorThatWasNotPresentedIsNotFound`,
`TestATrustAnchorChainIsNotHeldToAKeyUsageTheRFCDoesNotAsk`,
`TestABareAnchorKeyNobodyPresentedIsUndetermined`,
`TestAnExpiredAnchorIsUndetermined`,
`TestAnExpiredLeafUnderAnAnchorDoesNotMatch`,
`TestRecordsASenderDoesNotUseForSMTPAreNotUsable`,
`TestEveryMatchingTypeMatches`, `TestOneMatchingRecordAmongSeveralIsEnough`,
`TestWithoutACertificateNothingIsEstablished`,
`TestADANERecordIsCheckedAgainstWhatItsExchangerPresented`,
`TestTheStatesBeforeACertificateAreSaidAsThemselves`,
`TestNoBindingIsClaimedWhereNothingWasChecked`,
`TestTheReportsDANEWordsAreTheCheckersWords`,
`TestAValidatedBindingThatDoesNotHoldIsGraded`,
`TestABindingNotReportedValidatedIsNamedAndNotGraded`,
`TestWhatNoSenderUsesAndWhatWasNotEstablishedAreNotGraded`,
`TestAMatchIsSaidWithWhetherItValidated`,
`TestTheMailPathSaysWhetherTheBindingsWereChecked`,
`TestEachDANEBindingIsARowInThePagesWords`,
`TestThePageReadsTheDANEFieldsTheAPISends`,
`TestANameWithNoMXIsNotANameThatDoesNotExist`, `TestAShortMailRecordIsRefused`,
`TestDANEIsAskedOnlyBeneathTheExchangersTheDomainNamed`,
`TestANullMXEndsTheQuestionsAboutDelivery`,
`TestAnAddressIsAcceptedAndTheLocalPartIsDropped`,
`TestAMailAddressIsAcceptedAsItsDomain`,
`TestThePageSendsOnlyTheDomainOfAnAddress`,
`TestAnUnusableEHLONameIsRefusedAtStart`,
`TestTheEHLONameIsCheckedAndReachesTheService`,
`TestAnUnusableEHLONameStopsTheCommand`, `TestTheEHLONameReachesTheMailCheck`,
`TestTheAddressIsSplitWhereTheDomainBegins`,
`TestTheMailPathIsDescribedAndNeverGraded`,
`TestAnAnnouncedMTASTSPolicyIsNotAReadOne`,
`TestTheThreeDANEStatesAreKeptApart`,
`TestNothingIsLookedUnderWithoutASelector`, `TestAKeyIsReadWithItsSize`,
`TestAKeyBelowTheFloorIsWeak`, `TestAnEmptyKeyIsRevokedRatherThanBroken`,
`TestATestingKeyIsSeen`, `TestOnlyARecordThatAnnouncesItselfIsAKey`,
`TestAFailedLookupIsNotAnAbsentKey`, `TestWhereASelectorCameFromIsKept`,
`TestEveryDocumentedSelectorNamesItsProvider`,
`TestMigadusSelectorsAreDocumented`, `TestASelectorIsAskedAboutOnce`,
`TestTheSelectorListIsBounded`, `TestTheNameAskedAboutIsWhereAKeyLives`,
`TestASelectorThatHeldNothingIsNotDescribed`,
`TestAReportSaysWhichSelectorsWereTried`,
`TestAnAbsenceMeansDifferentThingsByWhoNamedTheSelector`,
`TestOnlyTheKeySizeIsGraded`, `TestARecordReachedThroughACNAMEIsRead`,
`TestARecordForAnUnrelatedNameIsStillSkipped`, `TestACNAMELoopEnds`,
`TestTheOnlyAddressAskedForIsTheOneRFC8461Names`, `TestThePolicyIsRead`,
`TestOnlyTheThreeModesAreRead`, `TestAnUnknownKeyDoesNotDiscardThePolicy`,
`TestOnlyASuccessfulResponseIsAPolicy`, `TestAnEnormousBodyIsBounded`,
`TestTooManyPatternsAreSaidToBeCut`,
`TestAFileMissingWhatAPolicyNeedsIsNotAPolicy`,
`TestAnInvalidPolicyIsGradedAndNotRead`,
`TestACutPolicyIsNotComparedWithTheExchangers`,
`TestAnInvalidPolicyIsGradedWithItsReason`,
`TestCoverageIsClaimedOnlyFromAWholeList`,
`TestAFailedFetchIsNotAnAbsentPolicy`,
`TestAPolicyIsNotReadOverAnUntrustedConnection`,
`TestTheCertificateMustNameThePolicyHost`,
`TestNoReasonNamesTheInfrastructure`, `TestTheWildcardCoversOneLabel`,
`TestAPolicyWithNoPatternsCoversNothing`,
`TestAHostileNameInThePolicyIsStripped`, `TestNoProxyIsConsulted`,
`TestTheDefaultFetcherUsesTheScannersTrustStore`,
`TestThePolicyModeReachesTheReport`,
`TestATestingPolicyIsDescribedRatherThanGraded`,
`TestThePolicyIsFetchedOnlyWhereTheZoneAnnouncesOne`,
`TestADeploymentThatDoesNotReadThePolicySaysSo`,
`TestAnExchangerTheEnforcingPolicyExcludesIsFound`,
`TestAPolicyCoveringEveryExchangerIsNotAFinding`,
`TestAFailedFetchIsNotAPolicyThatNamesNoMode`,
`TestCoverageIsNotClaimedWhereTheExchangersWereNotRead`,
`TestAnEnforcingPolicyThatCoversItsMailIsStrong`,
`TestAnEnforcingPolicyThatExcludesItsOwnExchangerIsGraded`,
`TestAnUncoveredExchangerUnderTestingIsSaidAndNotGraded`,
`TestAPolicyThatNamesNoModeIsGraded`, `TestAPolicyNamingNoExchangerIsGraded`,
`TestAPolicyNobodyReadIsNotGraded`,
`TestTheCacheLifetimeIsReportedAndNotGraded`,
`TestModeNoneIsReadAsAWithdrawal`, `TestTheSTSFindingsCiteTheirDocument`,
`TestTheCommandLineReadsTheSTSPolicy`, `TestTheMTASTSRowSaysWhatWasRead`,
`TestTheServiceFetchesTheSTSPolicyOnlyWhereItRequiredProof`,
`TestTheTrustStoreReachesTheMailCheck`,
`TestNoSenderRecipientOrMessageIsEverNamed`,
`TestAnExchangerOfferingSTARTTLSIsUpgradedAndJudged`,
`TestAnExchangerWithoutSTARTTLSIsMeasuredAsNotOffering`,
`TestTheCertificateIsJudgedOnTrustAndNameSeparately`,
`TestDataBeforeEncryptionStopsTheConversation`,
`TestTheEHLONameCannotCarryACommand`, `TestTheEHLONameIsTheClientsOwn`,
`TestExchangersAreAskedOnlyWhereTheDeploymentAllows`,
`TestANullMXIsNeverContacted`, `TestTheExchangersAskedAreBounded`,
`TestWhatAnExchangerAnsweredReachesTheReport`,
`TestTheDefaultExchangerProberCarriesTheStoreAndTheName`,
`TestAnEnforcingPolicyGradesAnExchangerThatCannotSatisfyIt`,
`TestAnExchangerSatisfyingTheEnforcingPolicyIsNotAFinding`,
`TestATestingPolicyDoesNotGradeTheExchanger`,
`TestAnUncoveredExchangerIsNotGradedTwice`,
`TestAnEnforcingPolicyAndAFailingExchangerAreGradedTogether`,
`TestTheMailLimitIsTrueWhenExchangersWereContacted`,
`TestTheCommandLineAsksTheExchangersWithItsName`,
`TestEveryFlagIsReadSomewhere`

### N15 — Over plain HTTP the service answers only to an address or to localhost

*Enforced in:* `internal/httpapi.Server.GuardHost`,
`internal/httpapi.servedHost`, `cmd/porchd.run`

*Guarded by:* `TestARebindingPageIsNotAnswered`,
`TestTheHostGuardIsInFrontOfEverything`, `TestEveryRefusalCodeCanBeProduced`

## Input

### N14 — The organisation promises once, and a product may only promise more narrowly

*Guarded by:* `TestTheOrganisationsPrivacyPageCarriesEveryPromise`,
`TestPorchsPrivacyPageCarriesItsPromises`,
`TestNoProductRedefinesWhatTheOrganisationUndertakes`,
`TestEveryUndertakingCanBeCheckedAndIsNamed`,
`TestTheOrganisationNamesNoProduct`,
`TestTheUndertakingsAreNotCopiedIntoAnyPage`,
`TestThePrivacyPageSaysWhichThirdPartiesAreAsked`,
`TestThePagesAreToldWhatThisInstallationAsks`

### I1 — One implementation of target parsing

*Enforced in:* `internal/scan.SplitTarget`

*Guarded by:* `TestSplitTarget`, `TestSplitTargetRejectsMalformedInput`

### I2 — Interior control characters are refused

*Enforced in:* `internal/scan.SplitTarget`

*Guarded by:* `TestSplitTargetRejectsMalformedInput`

### I3 — Error messages describe the rule, never repeat the input

*Enforced in:* `internal/httpapi`, in every `writeError` call

*Guarded by:* `TestErrorsDoNotEchoInput`

### I4 — Request bodies are capped before parsing

*Enforced in:* `internal/httpapi`, `http.MaxBytesReader` ahead of the decoder

*Guarded by:* `TestBodySizeLimit`

### I5 — Unknown JSON fields are refused

*Enforced in:* `internal/httpapi`, `Decoder.DisallowUnknownFields`

*Guarded by:* `TestRejectsMalformedBodies`

### I6 — Error messages do not describe this machine

*Enforced in:* `internal/tlsprobe.classifyHandshakeError`,
`internal/tlsprobe.legacyReason`, `internal/webprobe.classifyProbeError`

*Guarded by:* `TestHandshakeErrorsCarryNoInfrastructure`,
`TestReportFromAFailedProbeNamesNoAddress`,
`TestAFailedHopNamesNoInfrastructure`,
`TestAPolicyRefusalIsRecognisedWhateverItSays`,
`TestNoLegacyReasonNamesTheMachine`

### I7 — One host has one spelling

*Enforced in:* `internal/scan.canonicalHost`, `internal/httpapi.foldHost`

*Guarded by:* `TestSplitTargetFoldsSpelling`, `TestSplitTargetFoldsAddresses`,
`TestHostWithATrailingEmptyLabelIsRefused`, `TestFoldingIsStable`,
`TestTargetLimiterIgnoresSpelling`, `TestSpellingCannotBuyExtraScansOfOneHost`,
`FuzzSplitTarget`

### I8 — A DKIM selector is a DNS name, and a bound counts what it bounds

*Enforced in:* `internal/dkim.CheckSelector`, `internal/httpapi.handleScan`,
`cmd/porch-scan.checkSelectors`, `internal/web/assets/app.js`

*Guarded by:* `TestASelectorIsADNSName`,
`TestASelectorIsADNSNameAndCountsAsOne`,
`TestTheSelectorsAnOperatorNamesAreCheckedBeforeAnythingIsAsked`

## Availability

### A1 — Rate limiting is per client and cannot be chosen by the client

*Enforced in:* `internal/httpapi`, `clientKey` and `limiter`

*Guarded by:* `TestRateLimitIsPerClient`, `TestIPv6IsLimitedPerPrefix`,
`TestForwardedHeaderIgnoredWithoutTrustedProxy`,
`TestForwardedHeaderIsIgnoredFromUndeclaredNetworks`,
`TestForwardedHeaderIsReadFromDeclaredNetworks`,
`TestForwardedForReadsTheProxyLineNotTheClients`

### A2 — The rate limiter's memory is bounded

*Enforced in:* `internal/httpapi`, `limiter.maxKeys` and `limiter.sweepLocked`

*Guarded by:* `TestLimiterMemoryIsBounded`, `TestLimiterSweepsIdleClients`

### A3 — Concurrent scans are capped

*Enforced in:* `internal/httpapi`, `semaphore`

*Guarded by:* `TestConcurrencyLimit`

### A4 — Every endpoint has a budget

*Enforced in:* `internal/httpapi.Server.readLimited`

*Guarded by:* `TestReadEndpointsAreLimited`

### A5 — A full limiter does not become a lock

*Enforced in:* `internal/httpapi.limiter.makeRoomLocked`,
`internal/httpapi.clientKey`

*Guarded by:* `TestFullLimiterStillAdmitsNewClients`,
`TestForgedForwardedForCannotMakeNewKeys`,
`TestForwardedForReadsTheProxyLineNotTheClients`

### A6 — A refusal is cheap, not free, so a refusal is limited too

*Enforced in:* `internal/httpapi.Server.handleScan`, the read limiter at the
top

*Guarded by:* `TestCrossSiteRequestsAreRefused`,
`TestRefusalsBeforeTheScanAreLimited`, `TestReadAndScanBudgetsAreSeparate`,
`TestPollingReadsDoesNotSpendTheScanAllowance`,
`TestACrossSiteRefusalDoesNotSpendTheVisitorsScanBudget`

### A7 — Every reason a request can be refused is counted, and a counted reason can occur

*Enforced in:* `internal/httpapi.Server.refuse`,
`internal/tlsprobe.Report.BlockedDestination`,
`internal/webprobe.Report.BlockedDestination`

*Guarded by:* `TestEveryRefusalCodeCanBeProduced`,
`TestEveryCodeThisPackageRefusesWithIsCounted`,
`TestOnlyKnownRefusalCodesAreCounted`,
`TestANameThatResolvesOnlyWhereWeWillNotGoIsRecordedAsBlocked`,
`TestTheWebEndpointCountsABlockedDestination`,
`TestANameReachedOnOnePortIsNotABlockedDestination`,
`TestNoHopsIsNotABlockedDestination`,
`TestOnlyAPolicyRefusalSetsTheBlockedFlag`

### A8 — The per-target table regenerates faster than this service can spend it

*Enforced in:* `internal/httpapi.targetKeyBits`

*Guarded by:* `TestTargetTableOutrunsTheService`

### A9 — A shared limit does not answer questions about other people

*Enforced in:* `internal/httpapi.targetBurstMin`,
`internal/httpapi.targetLimiter.burstFor`

*Guarded by:* `TestSecretBurstBlursAProbeFromOutside`,
`TestSustainedTargetRateDoesNotDependOnTheBurst`,
`TestBurstStaysWithinItsBounds`,
`TestBurstIsStablePerBucketAndSecretPerProcess`

## Privacy

### P1 — Nothing about a request is recorded

*Enforced by:* the absence of logging in `internal/httpapi`, and
`httpapi.SilentErrorLog` passed to `http.Server.ErrorLog`

*Guarded by:* `TestNothingIsLogged`, `TestClientAddressesAreForgotten`,
`TestAnIdleClientIsForgottenWithoutAnotherRequest`,
`TestAnIdleTargetIsForgottenWithoutAnotherScan`,
`TestTheTimerSweepsEvenJustAfterARequestDid`,
`TestTheTargetTimerSweepsEvenJustAfterAScanDid`,
`TestAResultNotKeptIsSaidWithoutTheTarget`, `TestNotKeptKeepsOnlyTheReason`,
`TestConcurrentWritersKeepEveryRecord`, `TestALockIsWaitedForUnlessItIsStale`,
`TestALargeHistoryIsReadFromItsNewestEnd`, `TestTrimmingLeavesNoTemporaryFile`,
`TestATrimReplacesTheHistoryWhole`, `TestReadingAHistoryWritesNothing`,
`TestAReadDoesNotWaitForAnotherProcess`, `TestASelfHostedCopySaysWhatItDoes`,
`TestTheSelfHostedPrivacyPageFollowsTheConfiguration`,
`TestTheSelfHostedPageStatesTheRealRetentionPeriod`,
`TestTheDemonstrationKeepsItsOwnPrivacyPage`

### P2 — The target travels in a request body, not a URL

*Enforced in:* `internal/httpapi`, `POST /api/v1/scan` only

*Guarded by:* `TestMethodAndPathRouting`

### P3 — Responses are never cached

*Enforced in:* `internal/httpapi.setSecurityHeaders`, `Cache-Control: no-store`

*Guarded by:* `TestSecurityHeadersOnEveryResponse`

### P4 — Session resumption is not offered

*Enforced in:* `cmd/porchd` — `SessionTicketsDisabled`

### P5 — No plaintext listener exists

*Enforced in:* nftables, which opens 443 and nothing else; `porchd` binds one
listener

*Guarded by:* `TestHeadersOnEveryResponse`

### P6 — An installation behind a password shows nothing to whoever cannot sign in, and what it keeps is sealed by the password

*Enforced in:* `internal/access`, `internal/vault`, `cmd/porchd.createAccess`,
`cmd/porchd.retireSealed`, `cmd/porchd.run`, `internal/web.Configure`,
`internal/web.PublicPaths`

*Guarded by:* `TestNothingIsReachableWithoutSigningIn`,
`TestTheRightPasswordOpensASession`, `TestASessionEnds`,
`TestChangingThePasswordEndsOtherSessions`, `TestGuessingIsLimited`,
`TestASignInAllowanceIsPerIPv6Network`,
`TestAFullSignInTableRefusesRatherThanForgets`,
`TestAnotherSiteCannotUseTheSessionEndpoints`, `TestTheSessionTableIsBounded`,
`TestOnlyThePasswordOpensTheKey`, `TestThePasswordAndTheKeyAreNotOnDisk`,
`TestAnAlteredFileDoesNotOpen`, `TestAnAccessFileIsNeverReplacedByCreate`,
`TestChangingThePasswordKeepsTheKey`, `TestTheWorkFactorIsOWASPs`,
`TestAMissingAccessFileIsCreatedAndItsPasswordSaidOnce`,
`TestTheGateIsInFrontOfEverything`,
`TestTheSignInPageShowsNothingBehindTheGate`,
`TestOnlyTheSignInPageAndWhatItNeedsArePublic`,
`TestEveryPageBehindAPasswordOffersAWayOut`,
`TestTheSessionScriptDoesOnlyThat`,
`TestAFileSealedAtALowerWorkFactorIsRefused`, `TestAPublicPathIsExact`,
`TestAPasswordChangeNeedsALiveSession`, `TestOnlyThisPageMaySignIn`,
`TestTheSessionCookieCannotBePlantedByANeighbour`,
`TestAKeptReportComesBackWhole`, `TestNothingOnDiskIsReadable`,
`TestWithoutTheKeyNothingIsKeptOrRead`,
`TestAReportMovedToAnotherNameDoesNotOpen`,
`TestDeleteRemovesTheReportAndOnlyIt`, `TestTheHistoryIsNewestFirstAndBounded`,
`TestTheHandlerListsOpensAndDeletes`, `TestEveryReportAnsweredIsKeptWhole`,
`TestTheHistoryExistsOnlyBehindThePassword`,
`TestHistoryBehindAPasswordListsOpensAndDeletes`, `TestTheSealBindsTheName`,
`TestOnlyThisPackagesNamesAreNames`,
`TestAFileNameSaysNothingAndADateIsOnlyADate`,
`TestAReportNotKeptIsStillAnswered`,
`TestAKeptReportIsListedUnderTheNameAsTyped`,
`TestAPasswordIsTakenOnlyOverAPrivateTransport`,
`TestAPublicServiceWithoutAPasswordIsRefused`,
`TestAPasswordAndAPlainResultsDirectoryAreRefusedTogether`,
`TestEveryShippedConfigurationCarriesAPassword`,
`TestTheDomainListAddsListsAndRemoves`, `TestOnlyADomainIsAdded`,
`TestTheDomainListIsSealed`, `TestTheDomainListIsBounded`,
`TestTheDomainHandler`, `TestDomainsBehindAPasswordKeepsAListAndAsksEachOne`,
`TestANewPasswordMovesWhatTheOldOneKeptAside`,
`TestWhatTheListCannotShowIsCountedAndNeverTrimmed`,
`TestTheSessionScriptRecoversAndSignsOutOnlyOnSuccess`,
`TestASignInAddressIsForgottenOnceItsAllowanceRefills`,
`TestThePrivacyPageSaysWhatEachModeKeeps`

## Correctness of the report

### R1 — Verdicts come from the policy package and name their version

*Enforced in:* `internal/policy`; `tlsprobe` and `certinfo` only measure

*Guarded by:* `TestGradeCipherDelegatesToPolicy`, `TestReportNamesThePolicy`

### R2 — Every verdict cites a document, and the document is the current one

*Enforced in:* `internal/policy`, every rule carries `References`

*Guarded by:* `TestEveryFindingCitesASource`,
`TestEveryCertificateFindingCitesASource`

### R3 — What could not be measured is stated

*Enforced in:* `internal/tlsprobe`, the `Notes` field

*Guarded by:* `TestSupportedVersionsCarryTheCoverageNote`,
`TestDescribeTransparencySeparatesTheFourSituations`,
`TestEveryNoteInAReportCarriesAKind`, `TestAReportSaysItMeasuredOneHop`,
`TestAReportThatReachedNothingClaimsNoHop`,
`TestAReportNamesTheAddressesItReached`,
`TestAScanThatReachedTwoMachinesSaysSo`,
`TestTheAddressesReachedAreRecordedOnceEach`,
`TestEveryRegistryTLS13SuiteIsAskedAlone`,
`TestTheTLS13SuitesAServerAcceptsAreListedAndGraded`,
`TestASilentTLS13SuiteLeavesTheListIncomplete`,
`TestWithoutCalibrationOnlyTheNegotiatedSuiteIsListed`,
`TestAGoServerIsEnumeratedAtTLS13`,
`TestAProbeListsEveryTLS13SuiteTheServerAccepts`,
`TestAProbeSaysWhyTheTLS13SuitesWereNotEnumerated`,
`TestATLS13HelloNamesTLS13AndCarriesAKeyShare`,
`TestAnOrdinaryHelloDoesNotClaimTLS13`,
`TestTheVersionSupportedVersionsNamesIsRead`,
`TestAnExtensionBlockThatDoesNotAddUpLeavesTheLegacyVersion`,
`TestExtensionsPastTheBoundAreNotRead`,
`TestAddressesThatAnswerDifferentlyAreSaidToWithWhatEachAnswered`,
`TestEachAddressIsDialledAsItselfThroughTheDialler`,
`TestAddressesThatAnswerAlikeAreSaidToAnswerAlike`,
`TestAnAddressThatDoesNotAnswerIsNotEstablished`,
`TestTheAddressesAskedAreCappedAndTheReportSaysSo`,
`TestOneAddressAsksNothingMore`, `TestAnAddressListedTwiceIsAskedOnce`,
`TestCandidatesAreTheAddressesDialContextWouldTry`,
`TestAVersionAloneIsADifference`, `TestEachAddressIsARowInThePagesWords`,
`TestOneAddressPrintsNoAddressSection`,
`TestThePageReadsTheAddressFieldsTheAPISends`,
`TestTheReportSaysWhoseRootStoreDecided`

### R3a — No authority is asked, and the claim about revocation is made where the answer is known

*Enforced in:* `policy.GradeStapling`, in the notes

*Guarded by:* `TestNoAuthorityIsAskedOnAnyStapleOutcome`,
`TestThisPackageClaimsNothingAboutRevocation`,
`TestTheResponderIsAskedOnlyWhenAskedFor`,
`TestWhatAServiceAsksBeyondTheHandshake`,
`TestAskingTheResponderWithoutProofIsRefused`,
`TestAScanGivenAResponderAsksItAndReportsWhatItVerified`,
`TestAScanGivenNoResponderAsksNone`,
`TestTheRequestAsksAboutWhatARealResponderAnswered`,
`TestARequestNeedsTheCertificateAndItsIssuer`,
`TestARealResponderAnswerIsVerifiedAndRead`,
`TestAnAnswerThatDoesNotVerifyEstablishesNothing`,
`TestARedirectFromAResponderIsNotFollowed`, `TestAnOversizedAnswerIsRefused`,
`TestWhatIsAskedIsBounded`, `TestCredentialsInAResponderAddressAreStripped`,
`TestTheDefaultDiallerRefusesPrivateResponders`,
`TestAResponderAskedDirectlyThatSaysRevokedIsGraded`,
`TestARevocationSaidThreeWaysIsOneFinding`,
`TestAResponderAnswerOfUnknownOrGoodIsSaidAsItIs`,
`TestAQueryThatEstablishedNothingIsSaidAndAScanThatDidNotAskIsUnchanged`

### R3b — A stapled response is read, and what reading it cannot settle is said

*Enforced in:* `internal/ocsp.Check`, `internal/policy.GradeStapling`,
`internal/scan.issuerOf`, `internal/web/assets/app.js` (`revocationText`)

*Guarded by:* `TestAGoodResponseIsRead`, `TestARevokedCertificateIsReported`,
`TestAnUnknownStatusIsNotGood`,
`TestAResponseAboutAnotherCertificateIsRefused`,
`TestAResponseFromAnotherAuthorityIsRefused`, `TestAnExpiredResponseIsRefused`,
`TestAResponseFromTheFutureIsRefused`, `TestAResponseSignedByNobodyIsRefused`,
`TestADelegatedResponderIsAccepted`,
`TestACertificateCannotVouchForItselfWithoutTheDelegation`,
`TestAResponderFromAnotherAuthorityIsRefused`,
`TestAnUnsuccessfulResponseIsNotAStatus`,
`TestWithoutTheIssuerNothingIsClaimed`, `TestRubbishIsRefusedWithoutPanicking`,
`TestAnUnknownResponseTypeIsRefused`,
`TestTheStapledNoteSaysWhichOfTheThreeHappened`,
`TestTheShapesRealRespondersEmit`, `TestTheRightEntryIsFoundAmongSeveral`,
`TestRealResponsesFromRealAuthorities`,
`TestTheFixturesCoverBothSigningArrangements`,
`TestTheIssuerIsFoundWhereverItSitsInTheChain`,
`TestTheRevocationLineSaysWhetherTheResponseWasVerified`, `FuzzCheck`

### R3c — Transparency receipts are counted, and checked against a list that names its date

*Enforced in:* `internal/certinfo.embeddedSCTs` for the count,
`internal/ctlogs.Parse` and `internal/ctlogs.CheckEmbedded` for the check,
`internal/policy.DescribeTransparency` for what it means, joined in
`internal/scan.checkReceipts`

*Guarded by:* `TestParseSCTListCountsTimestampsAndLogs`,
`TestParseSCTListRefusesMalformedInput`, `FuzzParseSCTList`,
`TestDescribeTransparencySeparatesTheFourSituations`,
`TestLoggedNoteDoesNotClaimTheReceiptsWereVerified`,
`TestBothCountsAreReported`, `TestTransparencyReachesThePage`,
`TestTheCarriedListIsGooglesSigned`, `TestAListGoogleDidNotSignIsRefused`,
`TestALogWhoseIdentifierIsNotItsKeyIsRefused`,
`TestTheReceiptsInARealCertificateVerify`,
`TestReceiptsCheckedAgainstTheWrongIssuerDoNotVerify`,
`TestWithoutTheIssuerNothingIsVerified`,
`TestAReceiptFromALogNotInTheListIsUnknownRatherThanFalse`,
`TestThePrecertificateHasNoReceiptList`,
`TestAHandshakeReceiptSignsTheCertificateItself`,
`TestAMalformedReceiptIsUnreadable`, `TestDifferenceSeesWhatChanged`,
`FuzzReadReceipts`, `TestVerifiedReceiptsNameTheListTheyWereCheckedAgainst`,
`TestAVerifiedReceiptIsAPromiseAndNotAnInclusion`,
`TestUncheckedReceiptsAreSaidNotToBeVerified`,
`TestABadSignatureIsSaidAndNotGraded`,
`TestAReceiptFromAnUnlistedLogIsUnsettledNotFalse`,
`TestAnUnreadableReceiptIsUnsettled`,
`TestTheTransparencyLineSaysHowManySignaturesVerified`,
`TestCoverageSaysVerifiedOnlyWhenEveryReceiptWas`,
`TestTheReceiptsLimitNamesTheListAndNoPolicy`,
`TestAScanChecksTheReceiptsItCounts`,
`TestAChainWithoutItsIssuerVerifiesNothing`,
`TestNoCertificateMeansNothingChecked`, `TestAHandshakeReceiptIsCheckedToo`,
`TestTheTransparencyJoinChecksTheReceipts`,
`TestAListNamingTooManyLogsIsRefused`, `TestThePoisonExtensionIsRemovedToo`,
`TestAReceiptNamingAnotherHashIsUnsupported`,
`TestCheckExitsOneWhenTheLogsChanged`

### R3d — A limit of this scanner's network is not a fault of the server

*Enforced in:* `internal/safedial.SingleFamilyError`,
`internal/safedial.soleFamily`, `internal/tlsprobe.classifyHandshakeError`

*Guarded by:* `TestASingleFamilyIsNamedAndAMixedOneIsNot`,
`TestTheFamilyWrapperHidesNothing`,
`TestAnUnreachableHostSaysWhichFamilyWasTried`,
`TestAConnectTimeoutSaysPort25MayBeBlocked`,
`TestEveryExchangerTimingOutSaysPort25MayBeBlockedHere`

### R4 — Nothing measured is not the same as passing, or as failing

*Enforced in:* `internal/policy.Ungraded`, `policy.Worst`,
`policy.GradeVersion` (`version.unknown`), `policy.GradeCipher`
(`cipher.unrecognised`), `policy.GradeLeaf` (`cert.key-algorithm-unrecognised`)

*Guarded by:* `TestNothingMeasuredIsUngraded`,
`TestUnreachableTargetIsUngraded`,
`TestNothingIsLeftOutOfTheCertificateBlockBecauseItIsEmpty`,
`TestEveryDeclarationIsListedWhetherOrNotItWasThere`,
`TestTheContentPolicyAndThePageAreSaidInWords`,
`TestWhatTheSiteDeclaredReachesTheResult`,
`TestWhatTheSiteDeclaresIsDrawnInBothFaces`,
`TestTheProtocolIsAFactAndNotAFinding`,
`TestTheVersionOfHTTPThatCarriedTheResponseIsRecorded`,
`TestTheServiceDoesNotSpeakHTTP2`,
`TestTheMailPathDrawsItsRowsWhateverTheMXSays`,
`TestAChainNothingWasAttemptedAtSaysSo`,
`TestEveryStatedReasonIsTrueOfTheSuite`, `TestAClosedConnectionIsNotARefusal`,
`TestSilenceIsNotARefusal`, `TestOnlyAFatalAlertIsARefusal`,
`TestLegacyNeverTurnsNoVerdictIntoStrong`,
`TestAnExchangerThisClientCouldNotNegotiateWithIsNotGraded`,
`TestExchangersNotContactedAreSaidNotToHaveBeen`,
`TestAnUnmeasuredExchangerIsNotGradedUnderAnEnforcingPolicy`,
`TestARefusedGreetingIsNotMeasured`

### R4a — A verdict's stated reason is true of the thing it grades

*Enforced in:* `internal/policy.cipherRules`

*Guarded by:* `FuzzGradeCipher`, `TestEveryStatedReasonIsTrueOfTheSuite`,
`TestForwardSecrecyIsNeverDeniedOfASuiteThatHasIt`

### R4b — Trust and expiry are separate questions, asked separately

*Enforced in:* `internal/certinfo.trustedWithinValidity`

*Guarded by:* `TestAnExpiredUntrustedChainIsNotReportedTrusted`,
`TestTrustWithinValidityAsksARealQuestion`

### R5 — One insecure option makes the configuration insecure

*Enforced in:* `internal/policy.Worst`, used by `tlsprobe.summarise` and
`tlsprobe.mergeLegacy`

*Guarded by:* `TestWorstCaseAggregation`,
`TestAServerSpeakingOnlySSL3IsGradedInsecure`,
`TestAnExportSuiteAcceptedIsGraded`, `TestANullSuiteAcceptedIsGraded`,
`TestAFiniteFieldOrAnonymousSuiteAcceptedIsGraded`,
`TestAnUnansweredDHEOrAnonymousHelloIsSaidToBeUnsettled`,
`TestNeitherFamilyIsAskedWhenNothingAnswered`,
`TestALegacyFindingIsCountedOnce`

### R6 — Correct configuration is not penalised

*Enforced in:* `tlsprobe.summarise`, `policy.GradeLeaf`, `certinfo.Analyse`

*Guarded by:* `TestUnsupportedVersionsDoNotContributeFindings`,
`TestSelfSignedDoesNotAlsoReportUntrustedChain`,
`TestPresentIssuerIsNotAnIncompleteChain`,
`TestARefusalIsMeasuredAndCostsNothing`

### R7 — Results do not depend on the platform

*Enforced in:* `internal/certinfo.chainComplete`,
`internal/truststore.defaultStore`, `internal/rootstores.Parse`,
`internal/rootstores.Set.Judge`, `internal/certinfo.judgeStores`,
`internal/policy.StoresLine`, `internal/certinfo.resolveRoots`,
`internal/scan.Scanner.Roots`, `cmd/porchd`, `internal/truststore`,
`internal/webprobe.Prober.Roots`, `internal/webscan.Scanner.Roots`,
`internal/policy.TrustStoreUnreadable`, `internal/dnsclient`
(`resolver_unix.go`, `resolver_windows.go`, `Client.ask`),
`.github/workflows/ci.yml`

*Guarded by:* `TestMissingIssuerIsAnIncompleteChain`,
`TestPresentIssuerIsNotAnIncompleteChain`,
`TestARootThatDoesNotMatchItsFingerprintIsRefused`,
`TestAnUnknownStoreOrStatusIsRefused`, `TestEachStoreAnswersForItself`,
`TestTheDistrustDateIsTheLastDayTrusted`,
`TestTheCarriedStoresTrustARealChain`,
`TestTheSummaryIgnoresWhenAFileWasFetched`,
`TestChromeAnchorsAreReadWithTheirConstraints`,
`TestACertificateNotMatchingItsListedFingerprintIsRefused`,
`TestCheckExitsOneWhenAStoreChanged`, `TestTheStoresLineGroupsByWhatEachSaid`,
`TestAllStoresTrustingIsOneSentence`,
`TestAStoreThatRefusesIsSaidBesideTheVerdict`,
`TestAConditionalStoreIsUnsettled`, `TestADistrustDateThatAppliesIsSaid`,
`TestStoresNotUsedAreUnsettledWithTheReason`,
`TestTheTrustStoreLimitSaysWhatTheOtherStoresAre`,
`TestThePageReadsTheStoresLineTheAPISends`, `TestTheReportPrintsTheStoresLine`,
`TestAnalyseNamesWhatEachStoreMakesOfTheChain`,
`TestAFileNamingTooManyRootsIsRefused`,
`TestAnExpiredChainIsJudgedWithinItsValidity`, `TestTheSummaryNamesTheStore`,
`TestTheBestPathToARootDecides`, `TestBuildCarriesWhatEachStoreTrustsForTLS`,
`TestAnUnparseableRootMatchingItsFingerprintIsLeftOut`,
`TestTheRootsPassedInAreTheOnesThatDecide`,
`TestANilPoolBecomesTheSystemPoolRatherThanThePlatformVerifier`,
`TestEachPlatformResolvesToAPoolThatIsOnlyAPool`, `TestTheCarriedPoolIsACopy`,
`TestTheClientResolvesItsStoreAndKeepsNothingOpen`,
`TestTheServiceTakesItsStoreFromTheResolver`, `TestAPoolPassedInIsNotReplaced`,
`TestAnUnreadableStoreIsNotReportedAsAnUntrustedServer`,
`TestTheTestRootIsTheStoreAnalyseUses`,
`TestTheScannersTrustStoreIsWhatJudgesTheChain`,
`TestAnEmptyTrustStoreStopsTheServiceStarting`,
`TestADeadResolverIsFollowedByTheNextOne`,
`TestTheResolverThatAnsweredIsAskedFirstNextTime`,
`TestEveryResolverFailingKeepsTheFirstReason`, `TestAnEmptyResolverSetSaysSo`,
`TestAConfiguredResolverIsTheOnlyOneAsked`, `TestEveryNameserverIsRead`,
`TestAnUnusableNameserverIsSkipped`, `TestTheNameserverListIsBounded`,
`TestAFileWithNoNameserverIsNoResolver`, `TestAMissingResolvConfIsNoResolver`,
`TestANameserverListIsSplitHoweverItWasWritten`,
`TestARegistryStringIsDecoded`, `TestTheMachineReportsUsableResolvers`,
`TestTheResolverListDropsWhatCannotBeAsked`, `TestTheResolverListIsBounded`,
`TestTheResolverFlagReachesTheScanner`,
`TestNoResolverFlagLeavesTheMachinesOwnConfiguration`,
`TestTheResolverFlagReachesEveryLookup`, `TestEveryInstallationHasAResolver`,
`TestAResolverThatIsNotAnAddressAndPortIsRefused`,
`TestAServiceResolverReachesTheMailCheck`, `TestEveryReleasedPlatformIsVetted`,
`TestAnUnreadableStoreResolvesToAnEmptyPoolRatherThanNil`,
`TestTheRootsPassedInAreWhatVerifiesAWebChain`,
`TestAStoreWithoutTheAuthorityRefusesTheChain`,
`TestAnUnreadableStoreIsCarriedIntoTheReport`,
`TestAReadableStoreIsNotReportedAsUnreadable`,
`TestTheClientCarriesNoWeakeningTLSSetting`,
`TestTheScannersTrustStoreDecidesTheHandshake`,
`TestAProberWithItsOwnTrustStoreKeepsIt`,
`TestAnUnreadableStoreIsSaidInWordsRatherThanAsAnUnreachableSite`,
`TestAReadableStoreAddsNoNote`, `TestOneSentenceSaysTheStoreCouldNotBeRead`,
`TestTheConstructorGivesEveryCheckTheSameTrustStore`,
`TestReplacingTheWebScannerCannotDropTheTrustStore`

### R8 — Rules that change on a schedule are written as schedules

*Enforced in:* `internal/policy.MaxValidityDays`

*Guarded by:* `TestMaxValidityDaysFollowsTheSchedule`,
`TestValidityIsJudgedAtIssuance`

### R11 — A measurement that stopped early is not a measurement

*Enforced in:* `internal/tlsprobe.enumerateCiphers`,
`internal/tlsprobe.isNoSharedSuite`, `internal/tlsprobe.summarise`,
`internal/scan.settle`, `internal/policy.principalUnread`

*Guarded by:* `TestATruncatedSuiteListIsNotReportedAsComplete`,
`TestAnUnfinishedListCannotProduceStrong`,
`TestOnlyARefusalFinishesAnEnumeration`,
`TestAnUnfinishedTransportDoesNotEndStrong`,
`TestAnUnfinishedTransportKeepsWhatItFound`, `TestSettlingWithdrawsOnlyStrong`,
`TestUnreadPrincipalRecordsAreNotStrong`, `TestReadRecordsStillGradeAsTheyDid`

### R12 — A failure to measure is never drawn as a measurement

*Enforced in:* `internal/tlsprobe.VersionResult.Refused`,
`internal/tlsprobe.classifyHandshakeError`,
`internal/tlsprobe.suiteCoverageApplies`, `internal/web/assets/app.js`
(`outcomeCell`, `ciphers`, `transparencyText`), `cmd/porch-scan.printVersions`,
`cmd/porch-scan.printCiphers`

*Guarded by:* `TestOnlyAServerRefusalIsCalledOne`,
`TestARefusedVersionIsTheWordAlone`, `TestATruncatedListSaysSoWhereItIsShown`,
`TestAVersionThatCouldNotBeMeasuredIsNotCalledRefused`,
`TestATruncatedCipherListIsMarkedOnTheTable`,
`TestUnreadableTimestampsDoNotBecomeAMeasurement`,
`TestTheLimitsOfThisClientAreStatedWhenNothingWasAccepted`,
`TestTheClassesTheScriptAddsAreStyled`, `TestClientRefusalIsNotServerRefusal`,
`TestAVersionThatCouldNotBeMeasuredIsNotDrawnAsRefused`,
`TestASerialTooSmallToBeRandom`, `TestThePostQuantumQuestionHasThreeAnswers`

### R13 — An exit status is a verdict, and `ungraded` is not zero

*Enforced in:* `cmd/porch-scan.exitCode`

*Guarded by:* `TestUngradedIsNotAPass`,
`TestAnUngradedTargetIsNotHiddenByAGoodOne`,
`TestSeverityOutranksAnAbsentResult`

### R14a — A chain is graded, not only checked for trust

*Enforced in:* `internal/policy/chain.go`, `internal/certinfo.worstAcross`,
`internal/certinfo.issuerConstraints`

*Guarded by:* `TestMain`, `TestASoundIssuerRaisesNothing`,
`TestWhatAnIssuerIsGradedOn`, `TestBothGradersFireOnTheSameCryptography`,
`TestAnIssuerIsNotGradedOnWhatItIsNot`, `TestAWeakIssuerReachesTheVerdict`,
`TestARootIsNotGradedAndTheReportSaysWhy`,
`TestAnIssuerSubjectCannotRewriteTheReport`,
`TestTheVerdictIsTheWorstAcrossTheChain`,
`TestAFindingAboutAnIssuerReachesTheFindings`,
`TestASoundLeafTakesItsIssuersVerdict`, `TestTheTestRootIsTheStoreAnalyseUses`,
`TestAConstrainedIssuerIsDescribed`, `TestAnUnconstrainedIssuerSaysNothing`,
`TestARootsConstraintsAreNotReported`, `TestAConstraintCannotRewriteTheReport`

### R14 — A chain reachable at any version is a chain reachable

*Enforced in:* `internal/tlsprobe.differingChains`, `internal/scan.Scan`,
`internal/scan.Result.Findings`, `internal/scan.Result.Notes`

*Guarded by:* `TestAChainServedOnlyToOldClientsIsSeen`,
`TestTheSameLeafOverAnotherPathIsAnotherChain`,
`TestAChainDigestCoversEveryCertificateInOrder`,
`TestTheSameWholeChainEverywhereIsNoAlternate`,
`TestAChainDigestKnowsWhereEachCertificateEnds`,
`TestNoApplicationProtocolIsReported`,
`TestOneCertificateForEveryVersionProducesNoAlternate`,
`TestAWeakCertificateBehindAnOldVersionIsGraded`

### R15 — A rule that cannot fire is named, not counted

*Enforced in:* `internal/tlsprobe.probedVersions`,
`internal/tlsprobe.candidateSuites`, `internal/rawhello.SSL3`,
`internal/rawhello.Export`, `internal/rawhello.Null`, the list in
`internal/tlsprobe/reachable_test.go`

*Guarded by:* `TestEveryGradingRuleIsReachableOrNamed`,
`TestEveryUnreachableRuleIsInTheKnownGaps`

### R16 — One result, two renderers, one set of facts

*Enforced in:* `cmd/porch-scan.printReport`, `cmd/porch-scan.printCertificate`,
`internal/scan.Result.Notes`

*Guarded by:* `TestBothFacesOfTheReportShowTheSameFacts`,
`TestAReportSaysWhatWasMeasured`, `TestThePageReadsTheLegacyFieldsTheAPISends`,
`TestSSL3IsAVersionRowInTheSameWords`,
`TestTheHandWrittenHellosArePrintedWithWhatTheyFound`,
`TestSSL3HasOneRowAndItNamesTheSuite`,
`TestTheLegacySectionMatchesTheTerminal`,
`TestNothingIsPrintedForAQuestionNotAsked`,
`TestThePageReadsTheExchangerFieldsTheAPISends`,
`TestEachExchangerIsARowInThePagesWords`,
`TestExchangersNotContactedAreARowSayingWhy`

### R17 — A finding claims what was measured, not what it implies

*Enforced in:* the rationale of `cert.roca` in `internal/policy/cert.go`

*Guarded by:* `TestTheFingerprintReachesTheReport`

### R19 — A report says how much of the picture it reached, and never more than once

*Enforced in:* `internal/policy/coverage.go`, `internal/scan.coverageFacts`,
`internal/web/assets/app.js`, `internal/web/assets/style.css`

*Guarded by:* `TestCoverageNamesNothingItDidNotReach`,
`TestCoverageIsEmptyWhenNothingWasReached`,
`TestEachClauseWaitsForWhatItDescribes`, `TestCoverageIsOneSentence`,
`TestCoverageClaimsOnlyTheSuitesThisClientOffers`,
`TestTheCoverageLineSaysWhatWasReached`,
`TestAScanThatReachedNothingClaimsNoCoverage`,
`TestAWeakOrInsecureVerdictSaysWhatItMeans`,
`TestBothFacesSayWhatAVerdictMeansInTheSameWords`,
`TestTheVerdictIsGivenBeforeItIsExplained`,
`TestTheVerdictRowIsSeparateFromWhatIsWrittenUnderIt`

### R18 — A note carries the kind of claim it makes

*Enforced in:* `internal/policy/note.go`, `internal/policy/standing.go`;
`noteSections` in `cmd/porch-scan`; `NOTE_SECTIONS` in
`internal/web/assets/app.js`; `assets/method.html`

*Guarded by:* `TestEveryNoteInAReportCarriesAKind`,
`TestBothFacesNameTheSameNoteSections`,
`TestLimitsOpenOnlyWhenTheyAreTheWholeReport`,
`TestTheStandingLimitsAreNamedAndLinked`,
`TestTheReportPointsAtTheLimitsItDoesNotPrint`

### R9a — A CAA value is an authority and its parameters, not one string

*Enforced in:* `internal/policy.readable`, applied by
`internal/policy.describeAuthorities`

*Guarded by:* `TestCAAParametersAreNotMistakenForAuthorities`,
`TestAuthoritiesWithoutParametersAreUnchanged`

### R10 — A report cannot act on the display that shows it

*Enforced in:* `internal/certinfo.sanitise`, applied by `trimmer.text`;
`internal/certinfo.mixedScriptNote`, `internal/certinfo.confusableScripts`;
`internal/certinfo.distinguishedName`, `internal/ctsearch.clean`,
`internal/display.Mark`, `internal/dmarcreports`, `internal/securitytxt`,
`internal/markup`, `internal/spf`, `internal/dkim`,
`internal/webprobe.recorded`, `internal/dnsscan`

*Guarded by:* `TestAMonitorsAnswerCannotActOnTheDisplay`,
`TestNothingCanActOnTheDisplay`, `TestAContactCannotActOnTheDisplay`,
`TestAReportAddressCannotActOnTheDisplay`,
`TestAHostAPageNamesCannotActOnTheDisplay`, `TestARecordCannotActOnTheDisplay`,
`TestControlCharactersInCertificateFieldsAreNeutralised`,
`TestC1ControlsAreNeutralisedToo`, `TestTrimmingCutsOnARuneBoundary`,
`TestNothingCanRewriteHowTheReportReads`, `TestANameInTwoAlphabetsIsSaid`,
`TestALookalikeNameIsNotRewritten`,
`TestAnOrdinaryNameRendersExactlyAsItDidBefore`,
`TestAParsedOrdinaryNameRendersExactlyAsItDidBefore`,
`TestAnExtendedValidationNameIsReadable`,
`TestAnExtendedValidationSubjectReachesTheReport`,
`TestAValueThatLooksLikeTheGrammarIsEscaped`,
`TestWhatAServerSentCannotActOnADisplay`, `TestATextRecordCannotActOnADisplay`,
`FuzzReadPage`, `FuzzParsePolicy`, `FuzzParseSecurityTxt`, `FuzzSPFWalk`,
`FuzzDKIMRecord`, `FuzzReportDestinations`

### R20 — A value does not repeat the heading it is printed under

*Enforced in:* `internal/policy.DescribeCipher`

*Guarded by:* `TestACipherDescriptionDoesNotRepeatItsProtocolVersion`,
`TestEveryTLS13SuiteReportsTheSameKeyExchange`

### R21 — Where no document sets a threshold, the measurement is reported and not graded

*Enforced in:* `internal/policy/web.go`, `internal/policy/cookies.go`,
`internal/policy/headers.go`, `internal/tlsprobe.Fallback` (whether a
downgraded hello carrying `TLS_FALLBACK_SCSV` is refused: described, never
graded, because what a downgrade costs is the grade of the version it lands on)

*Guarded by:* `TestAShortMaxAgeIsDescribedAndNotGraded`,
`TestTheFallbackSignalIsReadInAllThreeWays`,
`TestTheFallbackIsNotAskedOfASingleVersion`,
`TestAnExchangerWithoutSTARTTLSIsDescribedAndNotGraded`,
`TestAnExchangerCertificateThatFailsIsDescribedAndNotGraded`,
`TestIncludeSubDomainsIsDescribedAndNotGraded`,
`TestATemporaryRedirectIsDescribedNotGraded`,
`TestAPermanentRedirectIsNotCalledTemporary`,
`TestNothingOnPortEightyIsObservedRatherThanGraded`,
`TestEveryWebFindingIsUsableOnItsOwn`, `TestAdviceIsReportedAndNotGraded`,
`TestACookieABrowserWillNotStoreIsGraded`,
`TestACorrectlySetCookieIsNotGraded`,
`TestACookieSetOverPlaintextIsNotChargedForMissingSecure`,
`TestNoCookiesProducesNothing`, `TestOneFaultAcrossManyCookiesIsOneFinding`,
`TestEveryCookieFindingCitesSomethingAndNamesItsRuleSet`,
`TestACookieNameIsCarriedThroughAsText`,
`TestTheCookieRulesReachAGradedReport`,
`TestACookieIsNotReadFromAHopThatFailed`,
`TestACookieCarriesTheTransportItWasSetOn`,
`TestCorsHeadersThatContradictEachOtherAreGraded`,
`TestEitherHalfOfTheCorsPairAloneIsNotGraded`,
`TestTheRecommendedHeadersAreReportedAndNotGraded`,
`TestNosniffIsReportedAndNotGraded`,
`TestAContentSecurityPolicySupersedesTheOlderFramingHeader`,
`TestAPolicyWithoutFrameAncestorsDoesNotHideMissingFramingProtection`,
`TestOnlyFrameAncestorsInAHeaderSupersedesXFrameOptions`,
`TestARepeatedDirectiveMakesTheHeaderNothing`,
`TestAPolicyFromAnotherHostIsNotThisHostsPolicy`,
`TestAnUnfollowedRedirectIsNotADestination`,
`TestAnUnfollowedChainIsNeitherGradedNorSound`,
`TestEmptyDirectivesAreNotRepeats`,
`TestAReportOnlyFrameAncestorsIsNotFramingProtection`,
`TestALocationTooLongToFollowIsUnfollowed`,
`TestAReportOnlyPolicyIsDescribedAsNotYetEnforcing`,
`TestAHostThatAnsweredNothingIsNotDescribedAsSendingNoHeaders`,
`TestASiteThatSendsEverythingIsToldNothing`, `TestTheReportedListIsStable`,
`TestTheHeaderRulesReachAGradedReport`,
`TestTheHeadersReadAreTheOnesOnTheResponseAVisitorLandsOn`

### R22 — One rule set grades one check, and every verdict names its own

*Enforced in:* `internal/policy` (`TLSVersion`, `WebVersion`,
`WebStandingLimits`); `internal/httpapi` (`checkNames`, `CheckCounts`,
`Snapshot.Checks`)

*Guarded by:* `TestEveryRuleSetNamesTheToolAndTheCheck`,
`TestTheWebLimitsAreItsOwn`, `TestEveryWebFindingIsUsableOnItsOwn`,
`TestTheChangeLogCoversTheCurrentPolicy`,
`TestThePublishedFieldsKeepTheirNamesAndTheirMeaning`,
`TestTheTopLevelFiguresAreTheTLSCheck`,
`TestEveryCheckBlockNamesItsOwnRuleSet`,
`TestAWebScanDoesNotMoveTheTLSFigures`, `TestACheckWithNoScansHasNoBlock`,
`TestOnlyKnownChecksAreCounted`, `TestEveryCountedCheckCanOccur`,
`TestAMailScanIsCountedAsOne`,
`TestAFileWithoutCheckBlocksRestoresIntoTheTLSBlock`,
`TestARollbackReadsTheTLSFiguresAndIgnoresTheRest`,
`TestRestoreFiltersUnknownChecks`,
`TestARestoredBlockDoesNotCarryTheOldRuleSetName`,
`TestSnapshotEqualityCoversTheCheckBlocks`,
`TestTheDailyFigureResetsForEveryCheck`,
`TestThePublishedCheckFiguresStandStillToo`,
`TestAWebScanIsCountedAgainstItsOwnCheck`, `TestTheWebEndpointAnswersAReport`

### R24 — The DNS check grades what breaks resolution, and reports the zone's own choices

*Enforced in:* `internal/policy.GradeDNS`, `internal/dnsscan`,
`internal/dnsclient.Client.AskServer`, `internal/httpapi.Server.dnsCheck`,
`cmd/porch-scan.runDNS`, `internal/web.consoleChecks`

*Guarded by:* `TestAZoneThatIsServedAndSignedReadsStrong`,
`TestTheDelegationIsGradedAgainstWhatIsRequired`,
`TestABrokenChainIsTheFindingThisExistsFor`,
`TestASHA1DigestIsSaidWhereTheChainWorks`,
`TestANameInsideAZoneIsNotGradedAsOne`,
`TestANameInsideAZoneSaysTheChainWasNotRead`,
`TestTheBoundariesAreAskedBeforeAnythingIsLookedUp`,
`TestTheSigningAlgorithmsAreGradedAsRFC8624SortsThem`,
`TestHowAbsentNamesAreProvedIsReadAndOnlyIterationsAreGraded`,
`TestANameServerThatIsAnAliasIsGraded`,
`TestAServerThatDoesNotAnswerForTheZoneIsFoundByAskingIt`,
`TestOnlyTheDomainsOwnServersAreAskedAboutOtherDomains`,
`TestWhatLooksLikeAnAnswerFromAServerAndIsNot`,
`TestWhatAskingAServerFoundIsDrawnInBothFaces`,
`TestTheDelegationIsAskedOnlyWhereProofWasRequired`,
`TestTheCommandLineAsksTheZonesOwnServers`,
`TestTheZoneAboveIsAskedWhichServersItHandsOut`,
`TestAParentThatWasNotAskedIsNotAgreement`,
`TestADelegationIsReadFromTheAuthoritySection`,
`TestOnlyAQuestionAboutServersReadsTheDelegation`,
`TestWhatTheZoneAboveHandsOutIsDrawnInBothFaces`,
`TestWhetherTheServersHoldTheSameCopyIsReadAndNotGraded`,
`TestWhetherTheZoneCanBeReadWholeIsAskedAndReported`,
`TestWhenTheSignaturesRunOutIsReadAndOnlyExpiryIsGraded`,
`TestWhenASignatureRunsOutIsReadFromTheAnswer`,
`TestASignatureIsReadOnlyWhereTheRecordsAre`,
`TestAShortSignatureIsRefusedRatherThanReadPastItself`,
`TestWhenTheSignatureRunsOutIsDrawnInBothFaces`,
`TestTheAddressTheZoneAboveHandsOutIsReadAndCompared`,
`TestTheAddressesInAReferralAreReadForTheNamesItDelegatedTo`,
`TestTheGlueTheZoneAboveHandsOutIsDrawnInBothFaces`,
`TestEveryLineSaysWhichRecordItCameFrom`, `TestATransferIsAskedForAndNotTaken`,
`TestATransferIsAskedThroughTheGuard`,
`TestATransferReplyMustAnswerTheQuestionAsked`,
`TestAServerThatHandsOutTheZoneIsDrawnInBothFaces`,
`TestASignedZoneSaysItsAlgorithmAndHowItProvesAbsence`,
`TestAnAliasIsReadAndItsTargetIsAskedAbout`,
`TestAnAliasAtTheTopOfAZoneIsGraded`, `TestTheAliasAtANameIsRead`,
`TestTheDigestAndTheTagBothHaveToAgree`, `TestTheDNSEndpointTakesADomain`,
`TestEveryCheckOfferedCanBeRunAndIsExplained`,
`TestEveryCheckNamedCanBeRunAndReachesItsOwnCode`,
`TestTheDNSReportSaysWhatWasReadAndWhatItMeans`,
`TestEveryCheckPointsAtItsOwnPage`,
`TestTheDNSReportSeparatesWhatWasReadFromWhatWasWritten`,
`TestThePublishedRecordsAreBounded`, `TestNoStringLiteralInAScriptIsLeftOpen`,
`TestEveryRuleSetNamesTheToolAndTheCheck`

### R23 — The policy read is the one a browser would hold

*Enforced in:* `internal/webscan` (`securePolicy`, `plaintextPolicy`, `hops`,
`answered`, `Grade`); `internal/policy/web.go` (`GradeReach`, `GradeHSTS`)

*Guarded by:* `TestThePolicyReadIsTheOneABrowserWouldHold`,
`TestAPolicySentOverPlaintextIsFoundSoItCanBeReported`,
`TestAFailedHopIsNotAResponseWithNoHeaders`,
`TestAWholeScanIsGradedAndCarriesItsEvidence`,
`TestACorrectlyReachedSiteIsStrongAndNotSilent`,
`TestAHostThatAnsweredNothingIsNotGradedForItsPolicy`,
`TestAChainEndingOnPlaintextIsNeverSound`,
`TestEveryReportCarriesTheLimitsOfTheMethod`,
`TestNoTLSLimitIsCarriedByAWebReport`,
`TestTheReportSerialisesWithoutItsSecrets`, `TestScanAndGradeAgreeOnTheHost`,
`TestATargetThatIsNotAHostnameIsRefusedBeforeAnythingIsAttempted`

## The page

### W1 — Nothing from a report reaches a markup parser

*Enforced in:* `internal/web/assets/app.js`,
`internal/web.contentSecurityPolicy`

*Guarded by:* `TestScriptCannotInjectMarkup`,
`TestPolicyForbidsScriptReachingAMarkupParser`,
`TestScriptBuildsClassNamesFromOneList`

### W2 — The page loads nothing from anyone else

*Enforced in:* `internal/web.setHeaders`

*Guarded by:* `TestNothingFromAnyoneElseIsEnforcedByAHeader`,
`TestContentSecurityPolicyAllowsOnlySelf`

### W2a — Only the demonstration says where it is, and it says what it is

*Enforced in:* `internal/web.render`, `internal/web.buildPlain`,
`internal/web/assets/layout.html`

*Guarded by:* `TestACrawlerIsToldWhatThisDeploymentIs`,
`TestEveryPageSaysWhichAddressItIs`,
`TestTheDemonstrationTitlesNameTheToolAndTheMaker`,
`TestPrivacyPageAnswersEveryUrgentQuestion`,
`TestASelfHostedCopySaysWhatItDoes`

### W3 — A table with the same columns is drawn with the same columns

*Enforced in:* `internal/web/assets/app.js`, `internal/web/assets/style.css`

*Guarded by:* `TestEveryCipherTableIsGivenTheSameColumns`,
`TestASuiteNameIsNeverBrokenOnScreen`,
`TestTheCipherTableScrollsInsideItsOwnContainer`,
`TestNothingIsLostOffTheEdgeOnPaper`, `TestTheClassesTheScriptAddsAreStyled`

### W4 — A shipped asset does not carry instructions for editing itself

*Enforced in:* `internal/web/assets/style.css`, `internal/web/assets/app.js`

*Guarded by:* `TestTheAssetsDoNotCarryInstructionsForEditingThemselves`

### W5 — A colour text is set in is legible on the paper it is set on

*Enforced in:* `internal/web/assets/style.css`

*Guarded by:* `TestEveryColourTextIsSetInIsLegible`,
`TestTheRuleColourIsNeverUsedForText`, `TestTheContrastArithmeticIsRight`,
`TestPorchsColourIsNeverAVerdictsColour`,
`TestTheBrandRedIsTheWordmarksAndTheOrganisations`,
`TestOnlyTheOrganisationsPagesKeepTheRed`

### W6 — A state is said in words and in colour, never by fading

*Enforced in:* `internal/web/assets/style.css`

*Guarded by:* `TestNoRestingStateIsFadedOut`, `TestTheWorkingStateIsLegible`

### W7 — The furniture is the right size and there is not too much of it

*Enforced in:* `internal/web/assets/style.css`,
`internal/web/assets/index.html`

*Guarded by:* `TestTheFooterLinksAreNotHeldToAProseMeasure`,
`TestTheLandingPageDoesNotStackNoticesUnderTheField`,
`TestTheWordmarkDeclaresATargetFloor`,
`TestTheScannerPageDoesNotRepeatThePrivacyPage`

### W8 — The project's addresses and a check's addresses are different addresses

*Enforced in:* `internal/web.pages`, `internal/web.moved`,
`internal/web.standingIn`, `internal/httpapi.New`

*Guarded by:* `TestTheProjectsPagesStayAtTheRootAndTheChecksDoNot`,
`TestTheRootIsAPageOnEveryBuildAndNothingStandsInForIt`,
`TestEveryInternalLinkResolves`, `TestEachCheckCallsItsOwnPaths`,
`TestEachScanPageDeclaresItsCheck`, `TestEachFooterLinksItsOwnSitesDocuments`,
`TestEveryAddressThisProjectSendsOutResolves`,
`TestBothScanPathsAreServedAndNeitherRedirects`,
`TestNeitherScanPathAnswersAGet`, `TestOldPathsRedirect`

### W8a — The organisation and Porch each answer at their own name

*Enforced in:* `internal/web/hosts.go`, `internal/web.render`,
`internal/web.buildPlain`, `internal/web/assets/layout.html`, `cmd/porchd.run`

*Guarded by:* `TestTheOrganisationAndPorchEachAnswerAtTheirOwnName`,
`TestTheRedirectsStayOnThisSite`, `TestAnyOtherNameIsServedEverything`,
`TestEveryPageIsAnsweredAtTheAddressItStates`,
`TestACrawlerIsToldWhatThisDeploymentIs`, `TestEveryPageSaysWhichAddressItIs`,
`TestEveryAddressThisProjectSendsOutResolves`,
`TestTheGateIsInFrontOfEverything`

### W9 — A report fits the screen it is read on

*Enforced in:* `internal/web/assets/style.css`

*Guarded by:* `TestAReportTableFitsAPhone`,
`TestAChainsShortColumnsHoldTheirWordsOnAPhone`,
`TestANotesCountWrapsRatherThanRunningOff`

## Disclosure

### D1 — A reporter can find a way to reach us, and the way is current

*Enforced in:* `internal/web`, the route table and `assets/security.txt`

*Guarded by:* `TestSecurityTxtIsServedAtTheWellKnownPath`,
`TestAnInstallationPublishesNoContactOfOurs`,
`TestLegacySecurityTxtPathRedirects`, `TestSecurityTxtHasTheRequiredFields`,
`TestSecurityTxtExpiryIsMovedByAPerson`,
`TestSecurityTxtDoesNotSendExclusionRequestsToSecurity`,
`TestFingerprintAgreesAcrossSources`, `TestTheServedKeyIsTheKeyWePublish`,
`TestTheServedPacketIsAPublicKeyPacket`

### R9a2 — What an issuer says it checked is reported and not graded

*Enforced in:* `internal/certinfo.validationLevel`, shown by `cmd/porch-scan`
and `internal/web/assets/app.js`

*Guarded by:* `TestTheValidationLevelIsNamed`,
`TestACertificateWithNoKnownPolicySaysNothing`,
`TestTheStrongestPolicyIsTheOneNamed`, `TestTheValidationLevelIsNotGraded`,
`TestTheValidationLevelIsOnTheFaceOfTheReport`,
`TestBothFacesOfTheReportShowTheSameFacts`

### R9 — Issuance policy is reported and not graded

*Enforced in:* `internal/dnsclient` for the query,
`internal/policy.DescribeIssuance` for what it means, joined in
`internal/scan.Scan`

*Guarded by:* `TestDescribeIssuanceSeparatesEveryState`,
`TestNotCheckedIsNotAnAccusation`, `TestProvenanceIsAlwaysStated`,
`TestEveryCheckedStateMentionsTransparency`,
`TestNoRecordSaysWhatFollowsFromIt`, `TestIssuanceIsOnTheFaceOfTheReport`,
`TestIssuanceSitsAboveTransparency`,
`TestAnUnfinishedWalkDoesNotClaimNobodyIsRestricted`

### N5 — A resolver's reply is treated as hostile

*Enforced in:* `internal/dnsclient`

*Guarded by:* `TestReplyMustAnswerTheQuestionAsked`,
`TestResponseCodesAreNotAllTheSame`, `TestCompressionPointersCannotLoop`,
`TestMalformedRecordsAreRefused`, `TestQuestionCaseIsRandomised`,
`TestRecordsForAnotherOwnerAreIgnored`, `TestOnlyTheAskedForOwnerIsKept`,
`TestOwnerMatchingIsCaseInsensitive`, `TestCompressedOwnerNamesMatch`,
`TestWhatAZonePublishesAboutItselfIsRead`, `TestAMalformedZoneRecordIsRefused`,
`TestHowAZoneHashesAbsentNamesIsRead`,
`TestAServerAskedDirectlySaysWhatItHoldsAndWhatItIs`,
`TestAServerThatRefusesIsNotAnAnswerAboutTheZone`,
`TestAServerIsDialledThroughTheGuard`, `TestAZoneThatDoesNotExistSaysSo`,
`TestARecordDoesNotHoldOnToTheReply`, `FuzzParseReply`, `FuzzSkipName`

## Supply chain

### S1 — No third-party dependencies

### S2 — Known vulnerabilities block a release

### S3 — The procedure that builds a release is pinned to that release

*Enforced in:* `.github/workflows/build-release.yml`,
`.github/workflows/reproduce.yml`, `scripts/release.ps1`

### S4 — A published release cannot be replaced by a workflow

*Enforced in:* `.github/workflows/build-release.yml`

### S5 — There is one build command, and it is the one the documents name

*Enforced in:* `scripts/build.sh`, `scripts/release.ps1`, `docs/verify.md`

### S7 — The toolchain is a supported one, and the analysis gates still run

*Enforced in:* `go.mod`, `.github/workflows/security-watch.yml`

*Guarded by:* `TestEveryAnalysisToolIsBuiltByTheModulesToolchain`,
`TestEveryGovulncheckIsTheSameOne`,
`TestTheWatchSaysAVulnerabilityOnlyWhenOneWasFound`,
`TestTheToolchainIsWatchedWeekly`

### S6 — What reaches `main` is what was signed

*Enforced in:* the repository's pull request settings (merge commits only);
`.github/commit-signers`

### S8 — A release is built only from source that passes its own gates

*Enforced in:* `.github/workflows/build-release.yml`, the two `Refuse to stage`
steps

### S9 — A published release is checked, in public, for a signature

*Enforced in:* `.github/workflows/reproduce.yml`, the `Check that the release
is actually signed` and `Check that the tag trusts the same keys` steps

### S10 — A binary can say which release it is

*Enforced in:* `scripts/build.sh`, `cmd/porch-scan.version`,
`cmd/porchd.version`, `cmd/porch-scan.versionLine`, `cmd/porchd.versionLines`

*Guarded by:* `TestTheBuildScriptStampsTheVersionSymbolThisProgramDefines`,
`TestAnUnstampedBinaryDoesNotClaimAVersion`,
`TestThePolicyVersionIsNotTheReleaseVersion`,
`TestTheVersionNamesEveryRuleSet`, `TestTheServiceVersionNamesEveryRuleSet`

### S11 — A rule set that changes says what changed

*Enforced in:* `internal/policy.Version`, `docs/policy-changes.md`,
`docs/releasing.md`

*Guarded by:* `TestTheChangeLogCoversTheCurrentPolicy`,
`TestTheChangeLogNamesRulesThatExist`,
`TestEveryRuleSetThatShippedNamesItsRelease`

### S12 — A tag cannot be moved or deleted

*Enforced in:* the repository's tag ruleset — restrict deletions and restrict
updates, both on

### S13 — The release procedure is written down, and its first instruction works

*Enforced in:* `docs/releasing.md`, `scripts/release.ps1`

*Guarded by:* `TestTheSignatureUploadedIsTheOneMadeForThatTag`,
`TestTheReleaseProcedureIsWrittenDown`,
`TestTheDocumentedInvocationIsTheOneThatWorks`,
`TestEveryRunCommandNamesItsRun`

### S14 — A gate goes red for its own subject, and for nothing else

*Enforced in:* `.github/workflows/fuzz.yml`, the classification in the fuzz
step

### S15 — The deploy is a step with a procedure, not the end of one

*Enforced in:* `docs/releasing.md`, and the private deployment notes

*Guarded by:* `TestTheDeployProcedureIsWrittenDown`,
`TestTheServiceIsNamedByThePathItIsAt`

### S16 — What somebody runs is what they verified

*Enforced in:* `Dockerfile`, `docker-compose.yml`, `docs/self-host.md`,
`cmd/porchd.trustStoreUsable`

*Guarded by:* `TestTheInstallNamesTheReleaseKeysFingerprint`,
`TestTheInstallCarriesTheReleaseKeyAndFailsClosed`,
`TestTheImageHasNoBaseSystem`, `TestTheComposeFileTakesAwayWhatItSays`,
`TestAnEmptyTrustStoreStopsTheServiceStarting`,
`TestSelfHostChecksTheSignatureTheWayVerifyMdDoes`,
`TestTheSelfHostingPageIsReachableAndItsLinksResolve`

### S17 — The image a server runs is the one the release signed

*Enforced in:* `internal/ociimage`, `scripts/build.sh`, `docker-compose.yml`,
`.github/workflows/build-release.yml`, `.github/workflows/reproduce.yml`,
`internal/web.pageImageDigest`

*Guarded by:* `TestTheComposeFilePinsEveryServiceToTheDigest`,
`TestTheSameBinariesMakeTheSameImage`, `TestTheImageRecordsNoTime`,
`TestADifferenceInTheComparisonSignsNothing`,
`TestTheImageIsTheTwoBinariesAndNothingElse`,
`TestTheImageStartsWhatTheDockerfileStarts`,
`TestTheReleaseImageIsPublishedByDigestAndChecked`,
`TestTheImageIsPushedByDigestAndReadBackExactly`,
`TestARegistryServingOtherBytesFailsTheCheck`,
`TestTheCredentialsGoNowhereButTheRegistry`,
`TestAPushWithoutCredentialsIsRefused`,
`TestThePorchPageShowsTheComposeFileThatShips`,
`TestALayoutIsReadBackAndATamperedOneIsRefused`

---

## Known gaps

Listed rather than hidden. A gap closed in code stays here until somebody
removes it, so a stale entry is a bug in this page.

- **Transparency receipts are counted, not verified.** R3c. Verifying one
  needs each log's public key, from a list browsers keep on their own
  schedule.
- **A stapled response's responder is not checked for revocation.** R3b.
  That would mean fetching from an address the scanned party chooses, and
  this scanner fetches nothing.
- **Revocation is seen only where the server staples.** R3a. About a third of
  hosts do. A report says so on its Revocation line.
- **The per-target limit still answers at its edge.** A9. A host checked many
  times in a window can be seen to be busy. That is a fact about load, not
  about a person.
- **Truncation defends enumeration, not confirmation.** A bucket identifier
  cannot be turned back into a name, but somebody who already suspects a name
  can test it.
- **`scan_failed` cannot be reached.** A7. The branch is defensive, and
  `TestEveryRefusalCodeCanBeProduced` names it.
- **A refused version and a version with no suite in common look the same.**
  R12. Both answer with a handshake failure, and the report says so.
- **Five grading rules cannot fire through this front end.** R15.
  `cipher.no-encryption`, `cipher.md5`, `version.unknown`,
  `cipher.unrecognised` and `cipher.not-current-practice`. The rules are
  correct; they are not coverage.
- **A lookalike alphabet is reported, not resolved.** R10. A name mixing
  Latin, Cyrillic or Greek raises a note. A name written wholly in one script
  that looks like a name in another raises nothing.
- **Four commits on `main` carry no signature.** S6. `1fdf674`, `cc163a3`,
  `01fc49f`, `7cd2cfa` were rebase-merged. The signed originals are the tag
  `signed/2026-08-20-docs-and-build`, with identical trees.
- **Each address of a name gets one handshake, not a full scan.** Up to
  eight addresses are asked alike. A machine that differs only in what else it
  would accept, behind the same preferred answer, looks identical.
- **The hosts a proven domain names have no budget of their own** (A05). Its
  exchangers and the revocation lists its certificates name are reached as a
  mail server or a browser would reach them. A per-exchanger budget, and
  fetching a list only for a chain that reaches a trusted root, each change
  what a report says and wait for a rule-set version.
- **One reader is not an audit.** Every file has been read, by the people who
  wrote it. That is not an independent review.
- **Prose drifts.** A test can only check the sentences somebody pinned.
  Where a claim can be pinned to a type rather than a phrase, it is.
