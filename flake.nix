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
      sqlFilter = path: _type: null != builtins.match ".*sql$" path;
      htmlOrCargoOrSql = path: type: (htmlFilter path type) || (sqlFilter path type) || (craneLib.filterCargoSources path type);
      src = lib.cleanSourceWith {
        src = craneLib.path ./.;
        filter = htmlOrCargoOrSql;
      };

      auditor = craneLib.buildPackage {
        inherit src;
        name = "auditor";
        nativeBuildInputs = [
          pkgs.sqlx-cli
        ];
        preBuild = ''
          export SQLX_OFFLINE_DIR=${craneLib.path ./.sqlx}
        '';
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
          pkgs.sqlx-cli
        ];
      };
    });
}
