package stream

var Camellia128CFB = NewStream(&streamAES{"camellia", 16, "cfb"})
var Camellia192CFB = NewStream(&streamAES{"camellia", 24, "cfb"})
var Camellia256CFB = NewStream(&streamAES{"camellia", 32, "cfb"})
