%%% File        : ed25519_multisig.erl
%%% Author      : Hans Svensson
%%% Description : Experimental ed25519-multisig
%%% Created     : 1 Oct 2021 by Hans Svensson
-module(ed25519_multisig).

-compile([export_all, nowarn_export_all]).

%% TODO: a proof of signature for OtherPubKeys?
sign_setup(#{secret := SK}, OtherPubKeys) ->
  <<Priv:32/bytes, Pub:32/bytes>> = SK,
  PubAll = lists:foldl(fun enacl:crypto_ed25519_add/2, Pub, OtherPubKeys),
  #{secret => Priv, my_pub => Pub, pub => PubAll}.

sign_step1(SignState = #{secret := SK}, Message) ->
  <<_:32/bytes, H:32/bytes>> = crypto:hash(sha512, SK),
  U = crypto:strong_rand_bytes(32),

  R = enacl:crypto_ed25519_scalar_reduce(crypto:hash(sha512, <<H/bytes, U/bytes, Message/bytes>>)),

  RG =  enacl:crypto_ed25519_scalarmult_base_noclamp(R),

  {RG, SignState#{r => R, rg => RG}};
sign_step1(_SignState, _Message) ->
  error(bad_sign_state).

sign_step2(SignState = #{secret := SK, r := R, rg := RG, pub := PubAll}, RGs, Message) ->
  <<Seed0:32/bytes, _:32/bytes>> = crypto:hash(sha512, SK),
  Seed = clamp(Seed0),
  RGAll  = lists:foldl(fun enacl:crypto_ed25519_add/2, RG, RGs),

  K = enacl:crypto_ed25519_scalar_reduce(crypto:hash(sha512, <<RGAll/bytes, PubAll/bytes, Message/bytes>>)),
  S = enacl:crypto_ed25519_scalar_add(R, enacl:crypto_ed25519_scalar_mul(K, Seed)),
  {S, SignState#{rg := RGAll, s => S}};
sign_step2(_SignState, _RGs, _Message) ->
  error(bad_sign_state).

sign_finish(SignState = #{rg := RGAll, s := S}, Ss) ->
  SAll = lists:foldl(fun enacl:crypto_ed25519_scalar_add/2, S, Ss),
  Sig = <<RGAll:32/bytes, SAll:32/bytes>>,
  {Sig, SignState#{sig => Sig, s := SAll}}.

%% Clamp a 32-byte value - i.e clear the lowest three bits of the last byte and
%% clear the highest and set the second highest of the first byte
clamp(<<B0:8, B1_30:30/bytes, B31:8>>) ->
  <<(B0 band 16#f8):8, B1_30/bytes, ((B31 band 16#7f) bor 16#40):8>>.
