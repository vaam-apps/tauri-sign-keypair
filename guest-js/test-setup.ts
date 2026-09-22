// IndexedDB is a browser API with no Node equivalent, and the WebCrypto backend
// is precisely the code that depends on it. `fake-indexeddb` is a real
// implementation of the spec rather than a stub, so what the tests exercise is
// the same transaction/keypath behaviour a browser would run.
import 'fake-indexeddb/auto'
