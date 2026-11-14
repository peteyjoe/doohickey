{
  description = "RP2350 Embassy/Rust firmware and Nuxt development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Nixpkgs 26.11 dropped Intel macOS; 26.05 is its last supported release.
    nixpkgs-intel-darwin.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      nixpkgs-intel-darwin,
      rust-overlay,
      ...
    }:
    let
      # Host architectures; the firmware is cross-compiled for the RP2350.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import (if system == "x86_64-darwin" then nixpkgs-intel-darwin else nixpkgs) {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
    in
    {
      formatter = forEachSystem (system: (pkgsFor system).nixfmt);

      devShells = forEachSystem (
        system:
        let
          pkgs = pkgsFor system;
          # The lock file pins what "latest" means for every team member.
          rust = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "llvm-tools-preview"
            ];
            targets = [ "thumbv8m.main-none-eabihf" ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rust # rustc, Cargo, rustfmt, Clippy, sources, LSP, and LLVM tools
              cargo-binutils # cargo size / objdump / nm, backed by Rust's LLVM
              probe-rs-tools # SWD flashing, debugging, RTT/defmt, cargo-embed
              picotool # RP2350 BOOTSEL flashing and ELF -> UF2 conversion
              openocd-rp2040 # Raspberry Pi fork: includes target/rp2350.cfg
              gdb # Nixpkgs enables all target architectures by default
              tio # UART / USB CDC serial terminal
              usbutils # lsusb

              nodejs_26 # Active LTS; includes plain npm and npx
              python3 # node-gyp and firmware utility scripts
              pkg-config
              cmake
              ninja
              git
            ];

            # Host-side Rust tools/tests can link these if needed. mkShell also
            # supplies a native C/C++ compiler and make (e.g. for node-gyp).
            buildInputs = with pkgs; [
              libusb1
              hidapi
              openssl
            ];

            shellHook = ''
              export DEFMT_LOG="''${DEFMT_LOG:-info}"
              echo "RP2350 dev shell: Rust (thumbv8m.main-none-eabihf), probe-rs, picotool, Node.js + npm"
            '';
          };
        }
      );
    };
}
