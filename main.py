import argparse
import os
import asyncio
import sys

# Local imports
from utils.log import Log
from modules.sql.sql import SQL


LOGGER = Log(debug=False)  # Default logger instance

def run_vuln_class(target, class_name: str, logger: Log):
    try:
        module_name = class_name.lower()
        module = __import__(f"modules.{module_name}.{module_name}", fromlist=[class_name])
        vuln_class = getattr(module, class_name)

        instance = vuln_class(target, logger)
        asyncio.run(instance.run())
    except ImportError as e:
        logger.error(f"Failed to import module for {class_name}: {e}")
    except AttributeError as e:
        logger.error(f"Class {class_name} not found in module: {e}")
    except Exception as e:
        logger.error(f"An error occurred while running {class_name}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Python script to run a vulnerability scanner on a target."
    )

    # debug (bool)
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode."
    )


    # sql (bool)
    parser.add_argument(
        "--sql",
        action="store_true",
        help="Enable SQL mode."
    )

    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="The target's ip or domain."
    )

    args = parser.parse_args()

    if not args.target:
        print("Error: --target argument is required.")
        sys.exit(1)

    logger = Log(debug=args.debug)

    if args.sql:
        run_vuln_class(args.target, "SQL", logger)

if __name__ == "__main__":
    main()