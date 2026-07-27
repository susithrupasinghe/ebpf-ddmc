;; EDDMC Evaluation — synthetic in-browser WASM hash-loop.
;;
;; A benign, self-authored FNV-1a-style mixing loop — NOT a real proof-of-work
;; algorithm and NOT derived from any live cryptojacking sample. It exists
;; purely to reproduce the OS-level *shape* the wasmbench / NoCoin corpora
;; describe: a WebAssembly module doing sustained, tight integer compute
;; across worker threads matching CPU core count.
(module
  (func $hash_loop (export "hash_loop") (param $iterations i32) (result i32)
    (local $i i32)
    (local $acc i32)
    (local.set $acc (i32.const 2166136261))
    (block $break
      (loop $continue
        (br_if $break (i32.ge_s (local.get $i) (local.get $iterations)))
        (local.set $acc
          (i32.mul
            (i32.xor (local.get $acc) (local.get $i))
            (i32.const 16777619)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )
    (local.get $acc)
  )
)
