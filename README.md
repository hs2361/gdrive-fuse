## DriveFS

Generally speaking, creating filesystems requires modifying kernel code. However, FUSE (Filesystem in USErspace) provides a software interface for Unix-like operating systems that allows non-privileged users to create, mount and access filesystems. This is achieved through a special "FUSE device" (/dev/fuse) that intercepts filesystem requests made to the kernel and forwards them to the user's application.

DriveFS is a read-only high-performance FUSE filesystem for Google Drive written in Rust. It allows you to mount your Google Drive locally and access files as if they were on your hard disk, with intelligent file caching and background streaming.

## Features

-   **Read-Only FUSE Mount**: Seamlessly mount Google Drive on Linux and perform standard filesystem operations.
-   **Intelligent Caching**: Implements a persistent file-based Least Frequently Used (LFU) cache to speed up repeated file access and minimize API usage.
-   **File Streaming**: Streams files in chunks, allowing immediate playback of media files without waiting for full downloads.
-   **Background Pre-Fetching**: Utilizes a multi-threaded downloader to concurrently pre-fetch and cache files that are likely to be accessed.
-   **Google Workspace Support**: Automatically exports Google Workspace files to usable formats on the fly:

    -   Google Docs → PDF
    -   Google Sheets → Excel (.xlsx)
    -   Google Slides → PowerPoint (.pptx)
    -   Google Drawings → SVG

-   **Auto-Unmount**: Optional flag to cleanly unmount the drive when the process exits.

## Prerequisites

-   Rust and Cargo
-   `libfuse` (on Linux) (can be installed with `dnf install fuse3-devel`)

## Google Drive API Setup

Follow the instructions in this [document](https://developers.google.com/workspace/drive/api/quickstart/python#set-up-environment) to enable the Google Drive API and create OAuth credentials. Download the client secret JSON file to your system.

## Setup & Configuration

1. **Create Configuration Directory**:
   The application looks for configuration in `~/.drivefs`.

```bash
mkdir -p ~/.drivefs

```

2. **Credentials**:

-   Rename the client secret JSON file to `client_secret.json` and place it in `~/.drivefs/client_secret.json`.
-   _Note: On first run, the app will prompt for authentication and generate a `credentials.json` token file in the same directory._

## Installation

Clone the repository and build with Cargo:

```bash
cargo build --release

```

## Usage

Run the binary by specifying a mount point:

```bash
# Basic usage
./target/release/drivefs /path/to/mountpoint

# With automatic unmounting on exit
./target/release/drivefs /path/to/mountpoint --auto-unmount

# Allow root access
./target/release/drivefs /path/to/mountpoint --allow-root

```

To unmount manually:

```bash
fusermount -u /path/to/mountpoint

```
