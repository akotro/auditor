{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    crane,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      craneLib = crane.mkLib pkgs;

      inherit (pkgs) lib;

      htmlFilter = path: _type: null != builtins.match ".*html$" path;
      htmlOrCargo = path: type: (htmlFilter path type) || (craneLib.filterCargoSources path type);
      src = lib.cleanSourceWith {
        src = craneLib.path ./.;
        filter = htmlOrCargo;
      };

      auditor = craneLib.buildPackage {
        inherit src;
        name = "auditor";
        postInstall = ''
          cp -r static $out/bin
        '';
      };
    in {
      packages.default = auditor;
      packages.auditor = auditor;

      devShells.default = pkgs.mkShell {
        packages = [
          pkgs.nil
        ];
      };
    });
}
