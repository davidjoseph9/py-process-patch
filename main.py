from patch_manager import PatchManager

DEFAULT_CONFIG_PATH = "config.yaml"


def main():
    PatchManager().load_config(DEFAULT_CONFIG_PATH)


if __name__ == '__main__':
    main()
