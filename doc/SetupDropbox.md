# Introduction

This guide shows how to have teslausb archive your recordings directly to a folder in [Dropbox](https://www.dropbox.com) whenever it is connected to your home wifi.

Compared to archiving to Dropbox with [rclone](SetupRClone.md), the Dropbox archive method:

- can archive only while connected to specific wifi networks, so it won't upload gigabytes of video over your phone's hotspot
- resumes interrupted uploads where they left off, instead of starting the file over, when you drive away in the middle of archiving
- doesn't upload files again after the car cut power to teslausb in the middle of archiving
- checks every upload against the content hash Dropbox computes before marking a file as archived
- needs nothing to be installed: it only uses Python, which is already on the Pi

# Step 1: Create a Dropbox app

teslausb accesses Dropbox through an app that you create in your own Dropbox account.

1. Go to the [Dropbox App Console](https://www.dropbox.com/developers/apps) and click "Create app".
1. Choose "Scoped access".
1. Choose the type of access:
   - "App folder" (recommended): teslausb can only access its own folder, `Apps/<app name>`, and nothing else in your Dropbox.
   - "Full Dropbox": only needed if you want the recordings in a folder outside of `Apps`.
1. Give the app a name, for example `TeslaUSB-yourname` (app names have to be unique), and click "Create app".
1. On the app's "Permissions" tab, check `files.metadata.read` and `files.content.write`, and click "Submit". Do this before authorizing teslausb in step 3, because the permissions are fixed at the time of authorization.
1. On the "Settings" tab, copy the "App key". teslausb doesn't need the app secret.

# Step 2: Configure teslausb

Add these lines to `teslausb_setup_variables.conf`, instead of the settings for any other archive method:

```
export ARCHIVE_SYSTEM=dropbox
export DROPBOX_APP_KEY='your_app_key'
export DROPBOX_PATH='/TeslaCam'
export DROPBOX_WIFI_SSIDS='your_home_ssid'
```

- `DROPBOX_PATH` is the Dropbox folder that recordings are archived to. It is created if it doesn't exist. For an "App folder" app it is inside the app's folder, so `/TeslaCam` becomes `Apps/<app name>/TeslaCam`. Use `/` to archive to the app's folder itself.
- `DROPBOX_WIFI_SSIDS` is optional. When it is set, teslausb only archives while connected to one of the listed wifi networks. Separate multiple network names with `|`, for example `'Home|Home 5G'`. Names must match exactly, including upper/lower case. When it isn't set, teslausb archives whenever it can reach Dropbox.

# Step 3: Authorize teslausb

teslausb needs your permission to use the app. There are two ways to give it.

## Option A: on the Pi

Run setup from an ssh session (see the [one-step setup instructions](OneStepSetup.md) for how to connect):

```
sudo -i
/root/bin/setup-teslausb
```

When setup gets to configuring the archive, it shows a link. Open the link in a web browser, click "Allow", and paste the access code that Dropbox shows back into the ssh session.

The first boot of a freshly flashed SD card runs setup without an ssh session, so setup stops with an error asking to authorize teslausb. You can then do the above at any time to finish setup. Alternatively, use the `none` archive method for the first setup, and switch to Dropbox later as described below.

## Option B: on another computer

This lets setup run unattended on the first boot. You need a computer with Python 3.

1. Download [`run/dropbox_archive/dropbox_archive.py`](../run/dropbox_archive/dropbox_archive.py) from the repository that you install teslausb from.
1. Run:
   ```
   python3 dropbox_archive.py authorize --app-key your_app_key --print
   ```
1. Open the link it shows in a web browser, click "Allow", and paste the access code that Dropbox shows.
1. It prints two lines like these. Add them to `teslausb_setup_variables.conf`:
   ```
   export DROPBOX_APP_KEY=your_app_key
   export DROPBOX_REFRESH_TOKEN=...
   ```

# Switching an existing teslausb to Dropbox

```
sudo -i
/root/bin/remountfs_rw
nano /root/teslausb_setup_variables.conf
/root/bin/setup-teslausb
```

In the editor, comment out the settings of the previous archive method, and add the settings from step 2.

# How archiving to Dropbox works

When teslausb connects to wifi and can reach Dropbox, archiving starts (after the usual `ARCHIVE_DELAY`). Saved clips are archived first, then sentry clips, track mode clips and finally recent clips (if `ARCHIVE_RECENTCLIPS` is enabled), so the most important recordings are safe first if archiving is cut short.

Files larger than 8 MB are uploaded in chunks, and the progress is saved to `/mutable/dropbox` after every chunk. When the connection drops in the middle of an upload, teslausb waits for up to two minutes for it to come back and then simply continues. If it doesn't come back, for example because you drove away, the upload continues from where it stopped the next time you get home. Dropbox keeps partial uploads for 48 hours; a file that was interrupted longer ago than that is uploaded again from the start.

A file only counts as archived after Dropbox has stored it and its content hash matches the file on the Pi. If it doesn't match, the copy in Dropbox is deleted, and the file is uploaded again the next time. Files in Dropbox are never overwritten: if Dropbox already has a different file with the same name, both are kept, and the new one gets a name like `2026-10-17_09-59-00-front (1).mp4`. Uploading a file that Dropbox already has with the same contents does nothing, so files are never stored twice.

If you have set up [notifications](ConfigureNotificationsForArchive.md), you also get one when archiving to Dropbox fails because Dropbox doesn't accept teslausb's credentials anymore, or because your Dropbox is full.

## Optional settings

| Setting | Default | Description |
| --- | --- | --- |
| `DROPBOX_WIFI_SSIDS` | any network | The wifi networks to archive on, separated by `\|`. |
| `DROPBOX_CHUNK_SIZE_MB` | `8` | The size of each uploaded chunk in MB, a multiple of 4 from 4 to 140. Larger chunks need fewer requests, but more has to be sent again after an interruption. |
| `DROPBOX_OFFLINE_TIMEOUT` | `120` | How many seconds to wait for a lost connection to come back before stopping. |
| `DROPBOX_APP_SECRET` | | Only needed for a refresh token that was not created with `dropbox_archive.py authorize`, and needs the app secret to be used. |
| `ARCHIVE_SERVER` | `api.dropboxapi.com` | The server that has to be reachable for archiving to start. |

# Credentials and security

teslausb stores the app key and refresh token in `/mutable/dropbox/credentials.json`, which only root can read. It doesn't need or store your Dropbox password or the app secret. The refresh token lets teslausb access your Dropbox until you revoke it, so:

- Use an "App folder" app, so that someone who gets hold of your teslausb can only get at the app's folder, and not the rest of your Dropbox.
- If you put `DROPBOX_REFRESH_TOKEN` in `teslausb_setup_variables.conf`, you can remove it from `/root/teslausb_setup_variables.conf` after setup, since teslausb keeps its own copy.
- If your teslausb is lost or stolen, go to the [Connected apps](https://www.dropbox.com/account/connected_apps) page of your Dropbox account settings, and remove the app.

To authorize teslausb again, for example after revoking its access or to switch to another Dropbox account, run `/root/bin/dropbox_archive.py authorize` as root. This doesn't require running setup again. When setup runs later, it keeps using this authorization instead of `DROPBOX_REFRESH_TOKEN`, unless you changed `DROPBOX_REFRESH_TOKEN` since.

# Troubleshooting

Run these as root (`sudo -i`):

- `/root/bin/dropbox_archive.py check` verifies the credentials, creates the archive folder if needed, and checks that teslausb can write to it.
- `/root/bin/dropbox_archive.py status` shows the configuration and any interrupted uploads that will be resumed.
- The archive log, `/mutable/archiveloop.log`, which is also shown in the teslausb web interface, has the details of every upload.

Common problems:

- "The Dropbox app doesn't have the 'files.content.write' permission": enable the permission on the app's "Permissions" tab in the App Console, then authorize teslausb again.
- "Dropbox did not accept the credentials (invalid_grant ...)": teslausb's access was revoked, so authorize teslausb again.
- Archiving doesn't start at home although `DROPBOX_WIFI_SSIDS` is set: check that it exactly matches the name of the network, which `iwgetid -r` shows.

To remove the credentials and all upload progress, delete `/mutable/dropbox`.

# Tests

The Dropbox archive method has tests that run against a fake Dropbox server, on any computer with Python 3:

```
python3 -m unittest discover -s tests -p 'test_*.py'
```
