%%% File        : crypto_misc.erl
%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 28 Sep 2021 by Hans Svensson
-module(crypto_misc).

-compile([export_all, nowarn_export_all]).

%% Try to do key-generation the manual way...
try_keygen() ->
  %% Let's get a 32 byte private key
  Priv = crypto:strong_rand_bytes(32),

  %% And let's compute the public key
  #{public := Pub} = enacl:sign_seed_keypair(Priv),

  %% Now let's replicate this, first SHA-512 hash the private key and extract first 32-bytes
  <<Seed0:32/bytes, _/binary>> = crypto:hash(sha512, Priv),

  %% We should really clamp the Seed, i.e clear the lowest three bits of the last byte and
  %% clear the highest and set the second highest of the first byte - but it doesn't seem
  %% entirely necessary(?)
  <<B0:8, Sx:30/bytes, B31:8>> = Seed0,
  Seed = <<(B0 band 16#f8):8, Sx/bytes, ((B31 band 16#7f) bor 16#40):8>>,

  %% Compute the public key point by scalarmult
  %% Note: this is an assertion
  Pub = enacl:crypto_ed25519_scalarmult_base(Seed).

%% Now lets try signing
try_sign() ->
  %% Now just grab a keypair.
  Priv = crypto:strong_rand_bytes(32),
  #{public := Pub, secret := SK} = enacl:sign_seed_keypair(Priv),

  %% Let the message be 32-bytes (normally it is a hash or similar)...
  Msg = crypto:strong_rand_bytes(32),
  io:format("Msg: ~140p\n", [Msg]),

  %% Builtin operation
  Sig = enacl:sign_detached(Msg, SK),

  %% Now manually

  %% Grab the Seed, also referred to as 'a' (clamped) and the Prefix
  <<Seed0:32/bytes, Prefix:32/bytes>> = crypto:hash(sha512, Priv),
  Seed = clamp(Seed0),
  io:format("a: ~140p\n", [Seed]),

  %% Compute r = H(prefix || msg)
  Rs0 = crypto:hash(sha512, <<Prefix/bytes, Msg/bytes>>),
  Rs = enacl:crypto_ed25519_scalar_reduce(Rs0),
  io:format("r: ~140p\n", [Rs]),

  %% Compute R = s⋅G (and since we want the computation to be invertible use
  %% the 'noclamp' version).
  R = enacl:crypto_ed25519_scalarmult_base_noclamp(Rs),
  io:format("R: ~140p\n", [R]),

  %% Compute k = H(R' || Pub || msg)
  Ks0 = crypto:hash(sha512, <<R/bytes, Pub/bytes, Msg/bytes>>),
  Ks = enacl:crypto_ed25519_scalar_reduce(Ks0),
  io:format("k: ~140p\n", [Ks]),

  %% Compute s = (r + k * a) mod L
  Ss = enacl:crypto_ed25519_scalar_add(Rs, enacl:crypto_ed25519_scalar_mul(Ks, Seed)),
  io:format("s: ~140p\n", [Ss]),

  %% Form the signature {R, s}
  Sig = <<R/bytes, Ss/bytes>>,

  io:format("\nManual signature matches enacl:sign_detach(Msg, SK)!! 👍\n"),

  ok.

try_verify() ->
  %% Now just grab a keypair.
  Priv = crypto:strong_rand_bytes(32),
  #{public := Pub, secret := SK} = enacl:sign_seed_keypair(Priv),
  io:format("Pub: ~140p\n", [Pub]),

  %% Let the message be 32-bytes (normally it is a hash or similar)...
  Msg = crypto:strong_rand_bytes(32),
  io:format("Msg: ~140p\n", [Msg]),

  %% Builtin operation
  Sig = enacl:sign_detached(Msg, SK),
  io:format("Sig: ~140p\n", [Sig]),

  %% Manual verify
  <<R:32/bytes, Ss:32/bytes>> = Sig,
  io:format("R: ~140p\ns: ~140p\n", [R, Ss]),

  Ks0 = crypto:hash(sha512, <<R/bytes, Pub/bytes, Msg/bytes>>),
  Ks = enacl:crypto_ed25519_scalar_reduce(Ks0),
  io:format("k: ~140p\n", [Ks]),

%%   Eight = <<8:8, 0:248>>,

  LHS = enacl:crypto_ed25519_scalarmult_base_noclamp(Ss),
  io:format("LHS:  ~140p\n", [LHS]),
  RHS = enacl:crypto_ed25519_add(R, neg_pt(enacl:crypto_ed25519_scalarmult_noclamp(Ks, Pub))),
  RHS2 = enacl:crypto_ed25519_add(R, pos_pt(enacl:crypto_ed25519_scalarmult_noclamp(Ks, Pub))),
  io:format("RHS:  ~140p\n", [RHS]),
  io:format("RHS2: ~140p\n", [RHS2]),


  KsPub = enacl:crypto_ed25519_scalarmult_noclamp(Ks, Pub),
  SG = enacl:crypto_ed25519_scalarmult_base_noclamp(Ss),

  Rpos = enacl:crypto_ed25519_sub(SG, pos_pt(KsPub)),
  Rneg = enacl:crypto_ed25519_sub(SG, neg_pt(KsPub)),

  io:format("R:    ~140p\n", [R]),
  io:format("Rpos: ~140p\n", [Rpos]),
  io:format("Rneg: ~140p\n", [Rneg]),

  true = (R == Rpos) orelse (R == Rneg),

  true = enacl:sign_verify_detached(Sig, Msg, Pub),
  ok.

try_multisig() ->
  %% https://crypto.stackexchange.com/questions/50448/schnorr-signatures-multisignature-support

  %% Alice creates a secret scalar 'a' and a secret hash key 'h' by picking a
  %% 32-byte private key PK and SHA512-hash it. Just like a normal signing
  %% keypair.  Alice share 'A' where 'A = a⋅G'.
  APK = crypto:strong_rand_bytes(32),
  <<Aa0:32/bytes, Ah:32/bytes>> = crypto:hash(sha512, APK),
  Aa = clamp(Aa0),
  AA = enacl:crypto_ed25519_scalarmult_base(Aa),

  %% Bob does the same thing.
  BPK = crypto:strong_rand_bytes(32),
  <<Bb0:32/bytes, Bh:32/bytes>> = crypto:hash(sha512, BPK),
  Bb = clamp(Bb0),
  BB = enacl:crypto_ed25519_scalarmult_base(Bb),

  %% Note: Alice and Bob should make certain that 'B' and 'A' respectively is a
  %% true public key. For example by signing something. Otherwise Bob can
  %% create phony 'B' from 'A' (or Alice a phony 'A' from 'B') that will allow
  %% him/her to sign unilaterally.

  %% Now both can compute their joint public key 'AB = A + B'. (This would be
  %% their address).
  AB = enacl:crypto_ed25519_add(AA, BB),

  %% Let's pick a message to sign.
  Msg = crypto:strong_rand_bytes(32),

  %% Alice picks a random 32-bytes value 'u', and computes 'r = H(h || u ||
  %% msg)', 'r' is kept secret but Alice shares 'R = r⋅G'.
  Au = crypto:strong_rand_bytes(32),
  Ar = enacl:crypto_ed25519_scalar_reduce(crypto:hash(sha512, <<Ah/bytes, Au/bytes, Msg/bytes>>)),
  AR = enacl:crypto_ed25519_scalarmult_base_noclamp(Ar),

  %% Bob does the same thing.
  Bu = crypto:strong_rand_bytes(32),
  Br = enacl:crypto_ed25519_scalar_reduce(crypto:hash(sha512, <<Bh/bytes, Bu/bytes, Msg/bytes>>)),
  BR = enacl:crypto_ed25519_scalarmult_base_noclamp(Br),

  %% Now they can both produce the first half of the signature 'R = AR + BR'.
  R = enacl:crypto_ed25519_add(AR, BR),

  %% Next Alice calculates 'k = H(R || AB || msg)' and 's = r + ka'.
  Ak = enacl:crypto_ed25519_scalar_reduce(crypto:hash(sha512, <<R/bytes, AB/bytes, Msg/bytes>>)),
  As = enacl:crypto_ed25519_scalar_add(Ar, enacl:crypto_ed25519_scalar_mul(Ak, Aa)),

  %% Bob does the same thing.
  Bk = enacl:crypto_ed25519_scalar_reduce(crypto:hash(sha512, <<R/bytes, AB/bytes, Msg/bytes>>)),
  Bs = enacl:crypto_ed25519_scalar_add(Br, enacl:crypto_ed25519_scalar_mul(Bk, Bb)),

  %% Now they can both produce the second half of the signature 's = As + Bs'.
  Ss = enacl:crypto_ed25519_scalar_add(As, Bs),

  %% The signature is R || s - just like a normal ed25519 signature.
  Sig = <<R/bytes, Ss/bytes>>,

  %% Finally check that we can successfully verify the signature.
  true = enacl:sign_verify_detached(Sig, Msg, AB),

  ok.



try_compare() ->
  %% Comparing to libsodium, example 20 in their sign.c test
%%   PKStr  = <<"0x1ca281938529896535a7714e3584085b86ef9fec723f42819fc8dd5d8c00817f">>,
  SKStr  = <<"0x8d135de7c8411bbdbd1b31e5dc678f2ac7109e792b60f38cd24936e8a898c32d1ca281938529896535a7714e3584085b86ef9fec723f42819fc8dd5d8c00817f">>,
  MStr   = <<"0x8ba6a4c9a15a244a9c26bb2a59b1026f21348b49">>,
  SigStr = <<"0xa1adc2bc6a2d980662677e7fdff6424de7dba50f5795ca90fdf3e96e256f3285cac71d3360482e993d0294ba4ec7440c61affdf35fe83e6e04263937db93f105">>,

%%   PK  = hexstring_decode(PKStr),
  SK  = hexstring_decode(SKStr),
  M   = hexstring_decode(MStr),
  Sig = hexstring_decode(SigStr),

  Sig2 = enacl:sign_detached(M, SK),
  io:format("Sig1: ~140p\n", [Sig]),
  io:format("Sig2: ~140p\n", [Sig2]),


  NonceStr = <<"0xbdb0afe38e5481b2faef4dd46319fe5100622a2d9527032ead64d0725d26a505f7d2d739d168125ad4b30dec18efaa7f206b2cf17e6ea4afcdfc47472de814e5">>,
  Nonce = hexstring_decode(NonceStr),

  <<Priv:32/bytes, _/bytes>> = SK,
  <<Seed0:32/bytes, Prefix:32/bytes>> = crypto:hash(sha512, Priv),
  <<B0:8, Sx:30/bytes, B31:8>> = Seed0,
  Seed = <<(B0 band 16#f8):8, Sx/bytes, ((B31 band 16#7f) bor 16#40):8>>,
  io:format("Seed: ~p\n", [Seed]),

  %% Compute r
  Rscalar0 = crypto:hash(sha512, <<Prefix/bytes, M/bytes>>),
  io:format("Rscalar0: ~140p\n", [Rscalar0]),
  io:format("Nonce:    ~140p\n", [Nonce]),

  RNonceStr = <<"0x0d867e77c24210c1b4764453c6a7f0304b8371b27e34fc423f3003034614f805">>,
  RNonce = hexstring_decode(RNonceStr),

  Rscalar = enacl:crypto_ed25519_scalar_reduce(Rscalar0),
  io:format("Rscalar: ~140p\n", [Rscalar]),
  io:format("RNonce:  ~140p\n", [RNonce]),

  RStr = <<"0xa1adc2bc6a2d980662677e7fdff6424de7dba50f5795ca90fdf3e96e256f3285">>,
  R = hexstring_decode(RStr),

  RP = enacl:crypto_ed25519_scalarmult_base_noclamp(Rscalar),
  io:format("R:  ~140p\n", [R]),
  io:format("RP: ~140p\n", [RP]),

  ok.


%% Clamp a 32-byte value - i.e clear the lowest three bits of the last byte and
%% clear the highest and set the second highest of the first byte
clamp(<<B0:8, B1_30:30/bytes, B31:8>>) ->
  <<(B0 band 16#f8):8, B1_30/bytes, ((B31 band 16#7f) bor 16#40):8>>.

neg_pt(<<B0_30:31/bytes, B31>>) -> <<B0_30/bytes, (B31 bor 16#80):8>>.
pos_pt(<<B0_30:31/bytes, B31>>) -> <<B0_30/bytes, (B31 band 16#7f):8>>.

hexstring_decode(Binary) ->
    case Binary of
        <<"0x", BinaryAsHexString/binary >> ->
            CharacterCnt = byte_size(BinaryAsHexString),
            case CharacterCnt rem 2 of
                0 when CharacterCnt > 0 -> pass;
                _ -> throw(invalid_hex_string)
            end,
            << << (hex_to_int(X)):4, (hex_to_int(Y)):4 >>
                  || <<X:8, Y:8>> <= BinaryAsHexString >>;
        <<"0x">> -> <<>>;
        <<>> -> <<>>;
        _ -> throw(invalid_hex_string)
    end.

hex_to_int(X) when $A =< X, X =< $F -> 10 + X - $A;
hex_to_int(X) when $a =< X, X =< $f -> 10 + X - $a;
hex_to_int(X) when $0 =< X, X =< $9 -> X - $0.

rev(Binary) ->
   Size = erlang:size(Binary)*8,
   <<X:Size/integer-little>> = Binary,
   <<X:Size/integer-big>>.


