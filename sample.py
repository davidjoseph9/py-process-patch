from patch_manager import PatchManager
import logging

SAMPLE_CONFIG_PATH = "examples/config.yaml"

logger = logging.getLogger()

def main():
    while True:
        try:
            patch_manager = PatchManager()
            patch_manager.load_config(SAMPLE_CONFIG_PATH)
        except KeyboardInterrupt:
            logger.info("Stopping...")
            break
    # Free memory after exiting


if __name__ == '__main__':
    main()
