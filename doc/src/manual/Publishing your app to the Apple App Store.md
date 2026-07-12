# Publishing your app to the Apple App Store
This tutorial walks you all the way from having no Apple account at all to having your NVGT game live on the App Store, and then updating it afterwards. It assumes you are working on **Windows** and that you do **not** own a Mac, because NVGT can build, sign, and package a complete iOS `.ipa` for you without any Apple hardware. The only Apple owned machines involved anywhere in this process are Apple's own review servers.

Read this guide start to finish before you begin. Apple's process has a lot of moving parts that reference each other (a certificate needs a request, a provisioning profile needs an identifier and a certificate, an upload needs an app record, and so on), so it is much easier if you already know where each piece is going to fit.

> Everything here was accurate against Apple's documentation at the time of writing. Apple changes wording, page layouts, and occasionally requirements fairly often. When a screen does not look exactly like it is described here, the underlying concept is almost always still the same; look for the button or field that does the same job.

## Overview: the whole journey at a glance
Here is the entire path so you have a mental map. Each step is explained in detail in its own section below.

1. **Decide whether you need a paid account yet.** You can install your unsigned game on your own iPhone for free to test it. You only need the paid Apple Developer Program to use TestFlight or to submit to the App Store.
2. **Create an app icon.** The App Store rejects apps without a proper icon, so set `#pragma icon` in your script before you do anything else.
3. **Enroll in the Apple Developer Program** (99 USD per year).
4. **Create a signing certificate and a `.p12` file** using OpenSSL on Windows. No Mac required.
5. **Register an App ID** (your bundle identifier) on the Apple Developer website. This must match your NVGT `product_identifier` exactly.
6. **Create and download a provisioning profile** that ties your App ID to your certificate.
7. **Tell NVGT to sign your app** using `#pragma` keys that point at your `.p12`, its password, and your provisioning profile, then compile to get a signed `.ipa`.
8. **Create your app's record in App Store Connect** and fill in all of the store metadata (screenshots, description, privacy answers, age rating, and so on).
9. **Upload the `.ipa`** to Apple using the free iTMSTransporter command line tool, which runs on Windows.
10. **(Optional but recommended) Test with TestFlight** before you go live.
11. **Submit for review**, wait for Apple, and release.
12. **Handle the result:** if Apple rejects the build you fix it and re-upload into the *same* version; once your app is live, shipping an update uses a *different* flow where you create a *new* version. These two flows are not the same, and mixing them up is one of the most common sources of confusion, so the difference is explained carefully at the end.

---

## Step 1: Do you need a paid account yet? Testing on a real device for free
Before you spend any money, you can and should run your game on a real iPhone or iPad to make sure it actually works. You do **not** need the paid Apple Developer Program for this, and you do **not** need a Mac. A free Apple ID (the same kind of account you use for the App Store as a normal customer) is enough.

The tool that makes this possible on Windows is **[Sideloadly](https://sideloadly.io/)**, a free application that installs any `.ipa` file directly onto a connected device. NVGT produces an `.ipa` even when you have not set up any signing (an "unsigned" `.ipa`), and Sideloadly signs it for you on the spot using your free Apple ID.

### How free "personal" signing works
When you sign an app with a free Apple ID, Apple issues you a temporary personal development certificate. This has real limitations you need to understand:

* **Apps stop working after 7 days.** A free personal certificate is only valid for 7 days. After that the app will refuse to launch and you must re-install it with Sideloadly to get another 7 days. (A paid developer account raises this to up to 1 year.)
* **Only 3 apps at a time.** A free account can have at most 3 sideloaded apps installed on the device simultaneously.
* **10 App IDs per 7 days.** Each different app you sign consumes one of a weekly budget of 10 App IDs. Re-installing the *same* app does not cost a new one, so day to day testing of a single game is fine.

These limits are Apple's, not NVGT's or Sideloadly's, and a paid membership removes the 3 app cap and extends the 7 days to a year.

### Setting up Sideloadly on Windows
1. **Install Apple's device drivers.** On Windows, Sideloadly needs the versions of **iTunes and iCloud downloaded from apple.com**, *not* the versions from the Microsoft Store. If you have the Microsoft Store versions installed, uninstall them first, then install the apple.com versions and reboot. This is by far the most common thing that goes wrong, so do it carefully.
2. **Install Sideloadly** from [sideloadly.io](https://sideloadly.io/).
3. **Connect your iPhone or iPad by USB.** Unlock it and tap **Trust** if it asks whether to trust this computer.

### Installing your game
1. Compile your game for iOS in NVGT to produce a `.ipa` file. You do not need any signing set up for this test.
2. Open Sideloadly. Your device appears in the device dropdown.
3. Drag your `.ipa` into the Sideloadly window (or browse to it).
4. Enter your **free Apple ID** in the Apple ID field and click **Start**. Enter your password when prompted. If your account uses two factor authentication you may need an app specific password (see Step 9, where app specific passwords are explained in full; the same kind of password works here).
5. Sideloadly signs and installs the app.

### Making the app launch: trust and Developer Mode
A freshly sideloaded app will not open until you do two things on the device itself:

* **Trust the developer certificate.** Go to **Settings > General > VPN & Device Management**, tap your Apple ID / developer profile, and choose **Trust**. (On older iOS versions this screen is called "Profiles & Device Management".)
* **Enable Developer Mode (iOS 16 and later).** Go to **Settings > Privacy & Security > Developer Mode**, turn it on, and restart the device. After the restart, confirm **Turn On** when prompted. This option usually only appears after you have installed at least one development signed app, which the Sideloadly install above satisfies. Developer Mode does not exist on iOS 15 and earlier and is not needed there.

Once both are done, the app launches like any other. Remember the 7 day clock: when the app suddenly refuses to open a week later, nothing is broken, you just re-run the Sideloadly install.

This free path is perfect for day to day development. When you are ready to distribute to other people, whether through TestFlight or the App Store, you need the paid account described next.

---

## Step 2: The app icon is mandatory
This step is short but critical: **the App Store rejects apps that do not have a proper icon.** There is no way around it, so set your icon up front.

In NVGT you do this with a single line in your script:

```
#pragma icon "icon.png"
```

Point it at a **square PNG**. A large source such as 1024x1024 is strongly recommended because Apple's store listing requires a 1024x1024 icon and NVGT scales your single image down to every other size each platform needs. When you set this pragma and build for iOS, NVGT automatically generates the compiled icon asset catalog that the App Store expects (this is the same `Assets.car` format Apple's own tools produce), so you do not need a Mac or Xcode to satisfy the requirement.

A few rules from Apple that you should respect in your source image to avoid a rejection or an automated upload failure:

* **No transparency.** The App Store icon must be fully opaque. An image saved with an alpha channel, even if it looks solid, can be rejected. Export a flat, opaque PNG.
* **No rounded corners.** Supply a full square. Apple applies the familiar rounded "squircle" mask itself; if you round the corners yourself you get an ugly double rounding.
* **Fill the whole square.** Do not leave large transparent or empty margins.

If you skip `#pragma icon` on iOS, NVGT produces **no icon at all** — it does not fall back to any placeholder or NVGT logo. No icon images are generated, no compiled asset catalog (`Assets.car`) is written, no loose PNG icons are placed in the bundle, and not even an icon entry is added to the `Info.plist`. Such a build can still be sideloaded for local testing (for example with Sideloadly), and it will install and run, but it has no home screen icon of its own.

For the App Store this omission is fatal in the hardest possible way: **an app with no icon is rejected by iTMSTransporter at upload time (Step 9), before it is ever sent to App Review.** You get an ITMS error and the build never even enters the review queue. So on iOS `#pragma icon` is not optional for a store submission; a build without it cannot be uploaded at all.

Be aware that NVGT's icon fallback behavior is **inconsistent across platforms**. On Android, omitting `#pragma icon` does *not* leave the app icon-less; instead NVGT ships SDL's default icon (a leftover from the SDL project template NVGT's Android build is based on). On iOS, omitting the pragma leaves the app with no icon whatsoever. Do not rely on either behavior; always set your own icon. For the full per platform behavior of the icon pragma, see the "compiling your project for distribution" tutorial.

---

## Step 3: Enroll in the Apple Developer Program
To use TestFlight or submit to the App Store you need a paid **Apple Developer Program** membership.

* **Cost:** 99 USD per membership year (shown in your local currency at checkout). It is billed annually.
* **Prerequisite:** an Apple ID (Apple Account) with **two factor authentication turned on**. This is required, no exceptions.

### Individual vs. Organization
You enroll as one of two types:

* **Individual / sole proprietor.** The simplest option. You enroll under your own legal name, which is what will appear as the seller on the App Store. **No D-U-N-S Number is required.** Use your real legal name in your Apple Account; a nickname or company name will delay approval.
* **Organization.** For a company or other legal entity that can enter into contracts (a corporation, LLC, limited partnership, and so on). This requires a free **D-U-N-S Number**, which identifies your business to Apple, and you must have the legal authority to bind the organization to agreements. DBAs, trade names, and branches are not accepted. Getting a D-U-N-S Number from Dun & Bradstreet can take several business days, so start early if you go this route.

If you are one person shipping a game, **Individual** is almost certainly what you want, and it is faster because it skips the D-U-N-S step.

### How to enroll
You can enroll either on the [Apple Developer website](https://developer.apple.com/programs/enroll/) or through the **Apple Developer app** on an iPhone or iPad. The app path can verify your identity using your device and a photo of your government ID, and in some regions (for example India) enrollment is only available through the app.

1. Make sure your Apple Account has two factor authentication enabled and your legal name is correct.
2. Start enrollment on the website or in the Apple Developer app.
3. Provide the requested identity and, for organizations, business information.
4. Pay the 99 USD fee.
5. Wait for approval. For individuals this is usually quick (Apple tells you to contact them if you have not been confirmed within 24 hours). Organizations take longer because Apple verifies your business, and there is no published fixed time, so plan for it to take a few days or more.

Once you are approved you gain access to two websites that you will use constantly:

* **[Apple Developer > Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources)** — where you manage certificates, App IDs, and provisioning profiles (Steps 4 to 6).
* **[App Store Connect](https://appstoreconnect.apple.com/)** — where you create your app's store listing, manage TestFlight, and submit for review (Steps 8 onward).

---

## Step 4: Create your signing certificate and `.p12` on Windows with OpenSSL
Apple's documentation assumes you make your signing certificate on a Mac using the Keychain Access app. **You do not need a Mac.** The certificate is just a standard cryptographic object, and you can produce everything Apple needs using **OpenSSL** on Windows. Apple's website accepts a certificate request generated by OpenSSL exactly the same as one from a Mac.

Install OpenSSL for Windows if you do not already have it (for example the "Win64 OpenSSL Light" build from the Shining Light Productions distribution, or the copy bundled with Git for Windows). Then work in an empty folder and run the commands below.

> Only the **Account Holder** or an **Admin** on your developer account can create a distribution certificate, and a team is allowed only **one** active Apple Distribution certificate at a time. Keep the files this step produces somewhere safe and backed up.

### 4a. Generate a private key
```
openssl genrsa -out distribution.key 2048
```
The key must be **RSA 2048 bit**. Keep `distribution.key` private and never share it; it is the secret half of your identity, and if you lose it your certificate becomes useless and you have to start over.

### 4b. Generate a certificate signing request (CSR)
```
openssl req -new -key distribution.key -out CertificateSigningRequest.certSigningRequest -subj "/emailAddress=you@example.com/CN=Your Name/C=US"
```
Replace the email, common name, and two letter country code with your own. Apple actually ignores the name you put here (it sets the real certificate name itself), so the important thing is simply that the command succeeds and produces the `.certSigningRequest` file. Use the slash separated `-subj` form shown here; on modern OpenSSL a comma separated subject can be misparsed.

### 4c. Upload the CSR and download your certificate
1. Sign in at [developer.apple.com/account](https://developer.apple.com/account).
2. Go to **Certificates, Identifiers & Profiles** and click **Certificates** in the sidebar.
3. Click the **+** (Create a New Certificate).
4. Under **Software**, choose **Apple Distribution**. (This is the modern certificate type that covers App Store and Ad Hoc distribution. An older "iOS Distribution" option may also appear; prefer **Apple Distribution**.)
5. Click **Continue**, then **Choose File**, and select your `CertificateSigningRequest.certSigningRequest`. Click **Continue**.
6. Click **Download**. You get a `.cer` file (for example `distribution.cer`).

### 4d. Convert the certificate and build the `.p12`
The downloaded `.cer` is in Apple's binary (DER) format. Convert it to PEM:
```
openssl x509 -inform der -in distribution.cer -out distribution.pem -outform pem
```

It is a good idea to also include Apple's intermediate certificate so your signing chain is complete. Download **AppleWWDRCAG3.cer** from [apple.com/certificateauthority](https://www.apple.com/certificateauthority/) and convert it too:
```
openssl x509 -inform der -in AppleWWDRCAG3.cer -out AppleWWDRCAG3.pem -outform pem
```

Now combine your private key and certificate into a single password protected `.p12` file, which is what NVGT will use to sign your app:
```
openssl pkcs12 -export -legacy -inkey distribution.key -in distribution.pem -certfile AppleWWDRCAG3.pem -out distribution.p12 -passout pass:YourStrongPassword
```

Two things matter a great deal here:

* **Set a real, non empty password** (replace `YourStrongPassword`). You will give this same password to NVGT in Step 7. Empty passwords are frequently rejected by signing tools.
* **Include the `-legacy` flag.** OpenSSL version 3 and later default to a newer encryption scheme for `.p12` files that many Apple related tools cannot read. `-legacy` produces the older, universally compatible format. Leaving this out is the single most common reason a `.p12` "mysteriously" fails to work later.

You now have `distribution.p12`, protected by a password you chose. That single file plus its password is your signing identity.

---

## Step 5: Register your App ID (bundle identifier)
Your app needs a unique identifier in reverse domain form, such as `com.yourcompany.yourgame`. This is the same value NVGT calls the **product identifier**, and the two must match **exactly** (it is case sensitive).

### Set it in NVGT
In your NVGT configuration (for example your `.nvgtrc` file) or via a pragma, set your product identifier:

```
#pragma config build.product_identifier = com.yourcompany.yourgame
```

Choose it carefully; once you have uploaded a build to Apple with a given identifier it is permanent and cannot be reused for anything else.

### Register the same identifier with Apple
1. In **Certificates, Identifiers & Profiles**, click **Identifiers** in the sidebar, then the **+**.
2. Select **App IDs** and click **Continue**.
3. On the "Select a type" screen choose **App** and click **Continue**.
4. Enter a **Description** (a human friendly label just for the portal).
5. Select **Explicit** and type your bundle ID in the **Bundle ID** field, exactly matching your NVGT `product_identifier` (for example `com.yourcompany.yourgame`). Use Explicit, not Wildcard.
6. Leave the default capabilities as they are unless you know you need something specific, then click **Continue** and **Register**.

The bundle ID here and your NVGT `product_identifier` being identical is what lets Apple connect your uploaded build to the right app record. A mismatch, including a difference in capitalization, breaks signing and upload.

---

## Step 6: Create and download a provisioning profile
A **provisioning profile** is the document that ties three things together: your App ID, your distribution certificate, and the permission to distribute through the App Store. NVGT reads it during signing.

1. In **Certificates, Identifiers & Profiles**, click **Profiles** in the sidebar, then the **+**.
2. Under **Distribution**, select **App Store Connect** (on older pages this is labeled just "App Store"). Click **Continue**.
3. Choose your **App ID** from the list (the one you registered in Step 5). Click **Continue**.
4. Select your **distribution certificate** (the Apple Distribution certificate from Step 4). Click **Continue**.
5. Give the profile a name you will recognize and click **Generate**.
6. Click **Download**. You get a `.mobileprovision` file.

There is no device selection step for an App Store profile (that only applies to Development and Ad Hoc profiles). Keep this `.mobileprovision` file with your `.p12`; you will point NVGT at both in the next step.

---

## Step 7: Sign your app from NVGT and build the `.ipa`
Now you tell NVGT to sign your game using the certificate and profile you just created. NVGT reproduces Apple's code signing byte for byte, so the `.ipa` it produces is a genuine, Apple acceptable signed app, all from Windows.

Add these three pragmas to your script (or the equivalent `build.*` keys in your configuration file):

```
#pragma ios_signing_identity "distribution.p12"
#pragma ios_signing_password "YourStrongPassword"
#pragma ios_provisioning_profile "distribution.mobileprovision"
```

* `#pragma ios_signing_identity` — path to your `.p12` from Step 4. Resolved relative to the script being compiled, like the asset and icon pragmas. (Config key: `build.ios_signing_p12`.)
* `#pragma ios_signing_password` — the password you set on the `.p12`. (Config key: `build.ios_signing_password`.)
* `#pragma ios_provisioning_profile` — path to your `.mobileprovision` from Step 6. (Config key: `build.ios_provisioning_profile`.)

When all three are present, NVGT signs the app during the iOS build and the resulting `.ipa` is ready to upload. If you leave them out, NVGT produces an unsigned `.ipa` (useful for the Sideloadly testing in Step 1, but not acceptable for the App Store).

> **Security note:** these pragmas put your `.p12` password in your source. If you share or open source your project, keep the signing values in a separate configuration file that you do not distribute (for example a local `.nvgtrc`) rather than hard coding them into a script you publish.

### Microphone and other permission descriptions
If your game uses the microphone, iOS requires your app to declare why, or the system will terminate it (and the App Store will reject it). Set:

```
#pragma microphone_usage_description "This game uses the microphone for voice chat."
```

Write a clear, honest sentence describing what you actually do with the microphone; a vague or missing description is a known rejection reason. There is a matching `#pragma camera_usage_description` for camera access. NVGT already sets a default camera description because the underlying media library links Apple's camera API even if your game never uses it; if your game never touches the camera you can set the camera description to an empty string to omit the prompt entirely.

Compile for iOS. You now have a signed `.ipa`, named after your project (for example `mygame.ipa`). Note its exact filename; you will need it in Step 9.

---

## Step 8: Understand version numbers, then create your app record
Before creating the store listing, you need to understand Apple's two separate version numbers, because they appear again in App Store Connect and in the upload metadata, and getting them wrong causes upload rejections.

### The two numbers
NVGT exposes both:

* **`build.product_version`** — the **marketing version**, the human friendly version your players see on the App Store, in the form `X.Y.Z` (for example `1.0.0`). Internally this becomes iOS's `CFBundleShortVersionString`. Digits and periods only.
* **`build.product_version_code`** — the **build number**, an internal counter that distinguishes one uploaded build from another. Internally this becomes iOS's `CFBundleVersion`. Conventionally you start at `1` and increase by one for every upload.

Set them in your configuration, for example:

```
#pragma config build.product_version = 1.0.0
#pragma config build.product_version_code = 1
```

### The rules that govern them
These rules are enforced by Apple's servers, so they are worth memorizing:

* **Every upload must have a higher build number than any previous upload of the same marketing version.** If you upload build `1` for version `1.0.0` and then try to upload build `1` again, Apple rejects it with a "duplicate bundle version" error. You must bump `product_version_code`.
* **A marketing version that has already been released to the public cannot be reused.** Once `1.0.0` is live, your next update must use a new, higher marketing version such as `1.0.1` or `1.1.0`.

The practical workflow these rules create is explained fully in Step 12, but here is the short version so the numbers you pick now make sense:

* **While getting your very first version approved:** keep the marketing version fixed (say `1.0.0`). If Apple rejects a build, you fix the problem, **increase only the build number** (`product_version_code` from `1` to `2`), and upload again. The marketing version stays `1.0.0` the whole time because `1.0.0` was never actually released.
* **Once your app is live and you want to ship an update:** you **raise the marketing version** (`product_version` to `1.0.1`, say) and you may reset the build number back to `1`.

### Create the app record in App Store Connect
Now create the listing:

1. Sign in to [App Store Connect](https://appstoreconnect.apple.com/) and go to **Apps**.
2. Click the **+** and choose **New App**.
3. Fill in:
   * **Platforms:** iOS.
   * **Name:** your app's public name (up to 30 characters).
   * **Primary Language.**
   * **Bundle ID:** choose the App ID you registered in Step 5 from the dropdown. (This is why you had to register it first.)
   * **SKU:** an arbitrary unique string you invent to identify the app internally (for example `yourgame001`). Users never see it. Remember what you choose, because this value is the **vendor ID** that appears in the upload metadata in Step 9.
   * **User Access:** leave as Full Access unless you manage a team with restricted roles.
4. Click **Create**.

Apple now assigns your app a numeric **Apple ID** (a long number, different from your login email and from your bundle ID). You can find it in your app's **App Information** page under General Information. Write it down; you need it for the upload metadata in Step 9.

### Fill in the required store metadata
Open your new app and complete every required field. Apple will not let you submit until these are done, and missing or placeholder content is a rejection reason:

* **Version number:** when you first create the app, App Store Connect pre fills the version as **`1.0`**. Change it to your real marketing version so it matches `build.product_version` in your build (for example `1.0.0`).
* **App icon:** the 1024x1024 icon. NVGT builds this into your `.ipa` from your `#pragma icon` (Step 2), so it travels with the build.
* **Screenshots:** at least one, taken on the currently required device sizes. At the time of writing Apple requires a **6.9 inch iPhone** screenshot (and if your app runs on iPad, a **13 inch iPad** screenshot); Apple scales these down for smaller devices. Because exact required pixel dimensions change as Apple releases new hardware, check the current **Screenshot specifications** page in App Store Connect Help rather than hard coding a size.
* **Description**, **keywords**, and a **Support URL**.
* **Privacy Policy URL** (required for all apps).
* **App Privacy:** answer the data collection questionnaire. Even if your game collects nothing, you must explicitly declare "No, we do not collect data from this app."
* **Age Rating** questionnaire.
* **Pricing and Availability** (free or a price tier, and which countries).
* **Category.**

---

## Step 9: Upload your `.ipa` from Windows with iTMSTransporter
Apple's build upload tool with a graphical interface, "Transporter," is only available on the Mac App Store. But the underlying command line uploader, **iTMSTransporter**, is a free, Java based tool that Apple provides for **Windows**, and it does the same job.

> **Important — Apple is retiring the `.itmsp` upload method.** As of Transporter 4.2, running the tool with `-f` prints:
>
> *"Deprecated Transporter usage. No action is required at this time. However, starting in 2026, you'll be required to use the `-assetFile` command instead of the `-f` command with your .ipa or .pkg files."*
>
> Apple's Transporter guide additionally states that delivering applications as `.itmsp` packages is deprecated, and that using `.itmsp` to *update* app content is already unsupported.
>
> This step therefore describes **three methods**:
>
> * **Method A (`-f` with an `.itmsp` package)** — the long standing method, described in 9c and 9d. It still works today and is the one most NVGT users have used successfully. It is deprecated and will eventually stop working.
> * **Method B (`-assetFile` with an `AppStoreInfo.plist`)** — Apple's official replacement, described in 9e. It is simpler once set up (no `.itmsp` folder, no `metadata.xml`, no Team ID/Apple ID/SKU to look up), but on Windows it needs one extra file that Apple expects Xcode to produce, so you must write that file by hand.
> * **Method C (`ios-uploader`)** — described in 9f. A third party open source tool that replaces iTMSTransporter entirely: one command, no Java, nothing to write by hand. It uses an undocumented Apple API, so it is a convenient fallback rather than something to depend on.
>
> **Try Method A first**, since it is the least surprising and is what this tutorial has always described. If it has stopped working, or you want to be ready for when Apple removes it, move to Method B. Method C is there if iTMSTransporter is fighting you.

### 9a. Install iTMSTransporter
Download it from Apple's **[Transporter User Guide](https://help.apple.com/itc/transporteruserguide/)**; the guide's install page links to the Windows installer (a file named like `iTMSTransporterToolInstaller_4.2.0.<build>.exe`). Run the installer, accept the license, and keep the default install location (typically `C:\Program Files\itms`). The tool bundles its own Java runtime, so you do not normally need to install Java separately. The command line program lives in the install's `bin` folder.

### 9b. Choose how you will authenticate
iTMSTransporter cannot log in with your normal Apple password because your account uses two factor authentication. There are two supported ways around this, and **either one works with both Method A and Method B** — authentication and delivery method are independent choices.

#### Option 1: an app specific password (simplest)
An **app specific password** is a special password that stands in for your account in tools like this:

1. Sign in at [appleid.apple.com](https://appleid.apple.com).
2. In **Sign-In and Security**, choose **App-Specific Passwords**.
3. Click **Generate an app-specific password**, give it a label (for example "Transporter"), and copy the generated password. It looks like `abcd-efgh-ijkl-mnop`.

You then pass `-u YOUR_APPLE_ID_EMAIL -p abcd-efgh-ijkl-mnop`.

Keep it somewhere safe. Note that changing your main Apple password automatically revokes all app specific passwords, so you would need to generate a new one.

#### Option 2: an App Store Connect API key (recommended)
An **API key** is a keypair issued to your team rather than to your personal login. It does not expire, it survives a password change, and it is safe to use from an automated build. This is what Apple now recommends.

1. In [App Store Connect](https://appstoreconnect.apple.com/), go to **Users and Access > Integrations > App Store Connect API**.
2. Generate a key with the **App Manager** role. Copy the **Issuer ID** (a UUID shown at the top of the page) and the **Key ID** (a short string next to your new key).
3. Download the private key file. It is named `AuthKey_<KEY_ID>.p8` and **Apple only lets you download it once**, so save it carefully.
4. Place that `.p8` file in one of the directories iTMSTransporter searches, most conveniently a folder named `private_keys` inside the directory you will run the command from, or `C:\Users\<you>\private_keys`.

You then pass `-apiKey YOUR_KEY_ID -apiIssuer YOUR_ISSUER_ID` and **omit `-u` and `-p` entirely**; mixing them is an error.

### 9c. Method A: build the `.itmsp` package (deprecated)
> **This is the deprecated method.** It still works today, but see the warning at the top of Step 9. If you would rather set up the replacement now, skip to 9e.

Used this way, iTMSTransporter does not upload a bare `.ipa`. It uploads a **package**, which is simply a **folder whose name ends in `.itmsp`** containing two files: your `.ipa` and a `metadata.xml` file describing it.

Create a folder, for example `MyGame.itmsp`, and copy your signed `.ipa` into it. Then you need two facts about the `.ipa`:

* **Its size in bytes.** In PowerShell: `(Get-Item "MyGame.itmsp\yourgame.ipa").Length`
* **Its MD5 checksum.** In Command Prompt: `certutil -hashfile "MyGame.itmsp\yourgame.ipa" MD5` (then remove the spaces from the printed hash to get the 32 character value).

Now create `metadata.xml` inside the same `.itmsp` folder. Here is a complete template; every value in capitals is something you fill in:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<package version="software5.4" xmlns="http://apple.com/itunes/importer">
    <team_id>YOUR_TEAM_ID</team_id>
    <software>
        <vendor_id>YOUR_SKU</vendor_id>
        <software_assets apple_id="YOUR_APP_APPLE_ID" bundle_identifier="com.yourcompany.yourgame" bundle_short_version_string="1.0.0" bundle_version="1">
            <asset type="bundle">
                <data_file>
                    <file_name>yourgame.ipa</file_name>
                    <size>YOUR_IPA_SIZE_IN_BYTES</size>
                    <checksum type="md5">YOUR_IPA_MD5_CHECKSUM</checksum>
                </data_file>
            </asset>
        </software_assets>
    </software>
</package>
```

What each field is and where it comes from:

* **`package version="software5.4"`** — the metadata schema version. Leave it as shown unless Apple's current Transporter guide specifies a newer one.
* **`team_id`** — your Apple Developer **Team ID**, a short alphanumeric string found in **Membership details** on the Apple Developer website.
* **`vendor_id`** — the **SKU** you invented when creating the app record in Step 8.
* **`apple_id`** — the numeric **Apple ID** Apple assigned to your app (from your app's App Information page in Step 8). This is a number, not your email.
* **`bundle_identifier`** — your bundle ID, exactly matching your NVGT `product_identifier` (for example `com.yourcompany.yourgame`).
* **`bundle_short_version_string`** — your marketing version. **This must match `build.product_version` in the build you are uploading** (for example `1.0.0`).
* **`bundle_version`** — your build number. **This must match `build.product_version_code`** (for example `1`).
* **`file_name`** — the exact filename of the `.ipa` inside the folder.
* **`size`** — the `.ipa` size in bytes you measured above.
* **`checksum`** — the MD5 you computed above.

The two version values are the same numbers you set in NVGT and entered in App Store Connect. Keeping all three in agreement (your build, this metadata, and the store listing) is essential; a mismatch causes the upload or the version association to fail.

### 9d. Method A: upload
Open a command prompt in the iTMSTransporter `bin` folder (or use its full path):

```
iTMSTransporter -m upload -f "C:\path\to\MyGame.itmsp" -u YOUR_APPLE_ID_EMAIL -p APP_SPECIFIC_PASSWORD -v eXtreme
```

Or, with an API key instead:

```
iTMSTransporter -m upload -f "C:\path\to\MyGame.itmsp" -apiKey YOUR_KEY_ID -apiIssuer YOUR_ISSUER_ID -v eXtreme
```

* `-m` is the mode.
* `-f` is the path to your `.itmsp` **folder**. This is the deprecated flag.
* `-v eXtreme` turns on detailed logging, which is invaluable when something fails.

> **Note on `-m verify`:** older versions of this tutorial suggested running `-m verify -f ...` first as a dry run. Apple's current Transporter guide states that **the `-f` option can no longer be used to verify an app** ("For apps, use the `-assetFile` option instead"), so that dry run may simply fail with Method A even when the real upload succeeds. Verification is available in Method B.

### 9e. Method B: upload with `-assetFile` and an `AppStoreInfo.plist`
This is the method Apple is moving everyone to. Instead of a package folder, you hand iTMSTransporter the `.ipa` directly:

```
iTMSTransporter -m upload -assetFile "C:\path\to\yourgame.ipa" -assetDescription "C:\path\to\AppStoreInfo.plist" -apiKey YOUR_KEY_ID -apiIssuer YOUR_ISSUER_ID -v eXtreme
```

Notice what is gone: no `.itmsp` folder, no `metadata.xml`, and no need to look up your Team ID, your app's numeric Apple ID, or your SKU. iTMSTransporter derives all of that from the bundle identifier inside the `.ipa` itself.

You can also dry run this one, which Method A no longer supports:

```
iTMSTransporter -m verify -assetFile "C:\path\to\yourgame.ipa" -assetDescription "C:\path\to\AppStoreInfo.plist" -apiKey YOUR_KEY_ID -apiIssuer YOUR_ISSUER_ID -v eXtreme
```

#### Why Windows needs `-assetDescription`
On a Mac, iTMSTransporter analyses the `.ipa` itself and works out everything it needs. On **Windows and Linux it cannot do that analysis**, and it fails with:

```
Unable to perform software analysis on Linux. Export an AppStoreInfo.plist from Xcode, and use the -assetDescription option.
```

Apple's suggested fix — "export it from Xcode" — is useless if you do not own a Mac. Fortunately the file is small and every value in it comes from the `.ipa` you already have, so you can write it yourself.

#### The `AppStoreInfo.plist` template
Create this file next to your `.ipa`. As with `metadata.xml`, every value in capitals is something you fill in:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>product-metadata</key>
    <dict>
        <key>archive-bytes</key>
        <integer>YOUR_IPA_SIZE_IN_BYTES</integer>
        <key>file-name</key>
        <string>yourgame.ipa</string>
        <key>packages</key>
        <array>
            <dict>
                <key>bundles</key>
                <array>
                    <dict>
                        <key>CFBundleShortVersionString</key>
                        <string>1.0.0</string>
                        <key>CFBundleVersion</key>
                        <string>1</string>
                        <key>bundle-identifier</key>
                        <string>com.yourcompany.yourgame</string>
                        <key>bundle-path</key>
                        <string>yourgame.app</string>
                        <key>bundles</key>
                        <array/>
                        <key>icons</key>
                        <array/>
                        <key>platform-display-name</key>
                        <string>iOS App</string>
                        <key>platform-id</key>
                        <integer>1</integer>
                    </dict>
                </array>
                <key>files</key>
                <array>
                    <dict>
                        <key>file-size</key>
                        <integer>MOBILEPROVISION_SIZE_IN_BYTES</integer>
                        <key>file-type</key>
                        <string>NSFileTypeRegular</string>
                        <key>file-data</key>
                        <data>BASE64_OF_EMBEDDED_MOBILEPROVISION</data>
                        <key>uti</key>
                        <string>com.apple.mobileprovision</string>
                        <key>path</key>
                        <string>yourgame.app/embedded.mobileprovision</string>
                    </dict>
                </array>
            </dict>
        </array>
    </dict>
</dict>
</plist>
```

What each field is and where it comes from:

* **`archive-bytes`** — the size of your `.ipa` in bytes.
* **`file-name`** — the exact filename of the `.ipa` (not a path).
* **`CFBundleShortVersionString`** — your marketing version. Must match `build.product_version` (for example `1.0.0`).
* **`CFBundleVersion`** — your build number. Must match `build.product_version_code` (for example `1`).
* **`bundle-identifier`** — your bundle ID, matching your NVGT `build.product_identifier`.
* **`bundle-path`** — the name of the `.app` folder **inside** the `.ipa`, which is `Payload/<something>.app`. For an NVGT build this is your project's base name plus `.app` (for example `yourgame.app`). Just the folder name, not the full path.
* **`platform-id`** — `1` for iOS. Leave it as shown.
* **`file-data`** — the **base64** of the `embedded.mobileprovision` file that NVGT placed inside your signed app bundle (Step 7). Note it is the *provisioning profile*, not the `.ipa`.
* **`file-size`** — the size in bytes of that same `embedded.mobileprovision`, **before** base64 encoding.
* **`path`** — where the profile lives inside the `.ipa`, relative to `Payload`, so `<your app>.app/embedded.mobileprovision`.

Everything else in the template is a fixed constant; copy it exactly.

#### Generating the file on Windows
An `.ipa` is just a ZIP archive, so PowerShell can pull the values out for you. Adjust the first two lines and run this in PowerShell; it prints every value you need to paste into the template:

```powershell
$ipa     = "C:\path\to\yourgame.ipa"
$appName = "yourgame.app"          # the folder inside Payload/

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip  = [IO.Compression.ZipFile]::OpenRead($ipa)
$prov = $zip.Entries | Where-Object { $_.FullName -eq "Payload/$appName/embedded.mobileprovision" }
$ms   = New-Object IO.MemoryStream
$prov.Open().CopyTo($ms)
$bytes = $ms.ToArray()
$zip.Dispose()

"archive-bytes : " + (Get-Item $ipa).Length
"file-name     : " + (Split-Path $ipa -Leaf)
"bundle-path   : $appName"
"file-size     : " + $bytes.Length
"file-data     :"
[Convert]::ToBase64String($bytes)
```

If the `$prov` line comes back empty, your `.ipa` is unsigned — go back to Step 7, because Method B cannot work without a provisioning profile inside the bundle.

#### If iTMSTransporter rejects the plist
The structure above is the minimum Apple's servers are known to accept, but Apple does not publish a schema for this file and iTMSTransporter may be stricter than the upload service itself. If it complains, the two things worth trying are:

1. **Convert the plist to binary format.** Apple's own tooling emits this file as a binary property list rather than XML. On Windows you can convert it with `plistutil` (part of libimobiledevice, which ships Windows builds): `plistutil -i AppStoreInfo.plist -o AppStoreInfo.bin.plist` — then pass the converted file to `-assetDescription`.
2. **Fall back to Method A or Method C** and report what failed, so this tutorial can be corrected.

> **A note on where this template came from, and NVGT's plan:** NVGT does not generate `AppStoreInfo.plist` today, exactly as it does not generate `metadata.xml`. The structure above was derived from the open source [ios-uploader](https://github.com/simonnilsson/ios-uploader) project, which builds the same file from an `.ipa` and successfully delivers builds to Apple with it. The proper long term fix is for **NVGT itself to emit `AppStoreInfo.plist` next to the signed `.ipa`**, since every value in it is already known at bundling time — at which point this whole section collapses into a single command.

### 9f. Method C: upload without iTMSTransporter at all
There is a third route that skips Apple's tooling entirely. [**ios-uploader**](https://github.com/simonnilsson/ios-uploader) is a small, open source, cross platform command line tool that speaks Apple's upload protocol directly. It builds the `AppStoreInfo.plist` in memory for you, so there is nothing to write by hand, and it needs no Java runtime and no Transporter install.

Install Node.js, then either run it on demand:

```
npx ios-uploader -u YOUR_APPLE_ID_EMAIL -p APP_SPECIFIC_PASSWORD -f C:\path\to\yourgame.ipa
```

or install it once:

```
npm install -g ios-uploader
ios-uploader -u YOUR_APPLE_ID_EMAIL -p APP_SPECIFIC_PASSWORD -f C:\path\to\yourgame.ipa
```

That is the whole procedure. It reads the bundle ID and both version numbers out of your `.ipa`, looks your app up on Apple's side, registers the build, uploads the file in parallel chunks, and reports the processing status.

Be aware of the trade offs before you rely on it:

* **It is not an Apple product and uses an undocumented API.** The project's own README warns that it "may stop working at any time without prior notice if Apple decides to change the API." It is actively maintained and works at the time of writing, but it carries a risk that Apple's own tool does not.
* **App specific passwords only.** It does not support App Store Connect API keys, so it is a weaker fit for automated builds.
* **No dry run.** There is no equivalent of `-m verify`; problems surface during Apple's processing stage rather than before the upload.
* Your `.ipa` must be signed, as with Method B.

It is an excellent fallback if iTMSTransporter is giving you trouble, and a genuinely convenient option for a one person project. For anything you depend on, prefer Method B.

### 9g. After the upload
Whichever method you used, Apple now **processes** the build on its servers. It becomes selectable in App Store Connect after processing finishes, which usually takes anywhere from a few minutes to about an hour. You will typically get an email when it is ready.

---

## Step 10: Test with TestFlight (recommended)
TestFlight lets real people install and test your build before it goes public. Testers install the free **TestFlight** app from the App Store and accept an invitation by email or via a link. TestFlight uses the very same uploaded build you just sent with iTMSTransporter, so there is no separate upload.

There are two kinds of testing, and the difference matters:

### Internal testing
* For members of your own App Store Connect team (people you have added with a role such as Admin or Developer).
* Up to **100 internal testers**.
* **No review required.** As soon as your uploaded build finishes processing, internal testers can install it. This makes internal testing the fastest way to get a build onto other people's devices.

### External testing
* For anyone else: your wider beta audience, invited by email or by a shareable **public link**.
* Up to **10,000 external testers**.
* **Requires Beta App Review.** The first build you give to external testers goes through a review by Apple (separate from, and lighter than, the full App Store review) before those testers can install. Later builds of the same version often skip a full re review.
* You must create at least one internal group before you can set up external testing.

### Using it
1. In App Store Connect, open your app and go to the **TestFlight** tab.
2. Answer the **export compliance** question about encryption if prompted (see the note below).
3. Create a tester group, add your build to it, and add testers (by email for internal, by email or public link for external).
4. Testers open the TestFlight app and install.

Two facts to keep in mind: TestFlight builds **expire after 90 days**, after which testers can no longer launch them; and passing Beta App Review is **not** the same as passing App Store review, so a build being fine on TestFlight does not guarantee App Store approval.

> **Export compliance:** App Store Connect asks whether your app uses non exempt encryption. Most simple games do not, and you can answer this once in the interface. If you never want to see the prompt, you can predeclare it, but for most NVGT games answering "no" (no non exempt encryption) when prompted is correct. If you are unsure, read Apple's guidance rather than guessing, because an incorrect declaration is a legal statement.

---

## Step 11: Submit for review and release
When you are happy with the build:

1. In App Store Connect, open your app's version (the `1.0.0` version you are preparing).
2. In the **Build** section, click the **+** (or **Add Build**) and select the processed build you uploaded in Step 9. It must have finished processing to appear.
3. Make sure every required metadata field from Step 8 is filled in.
4. Click **Add for Review**, then **Submit for Review**.

Your app's status moves through a series of states you can watch on the app's page:

* **Waiting for Review** — submitted, in Apple's queue.
* **In Review** — a reviewer is looking at it.
* **Pending Developer Release** — approved, waiting for you to press release (if you chose manual release).
* **Ready for Distribution** (older name: "Ready for Sale") — approved and, if set to release automatically, live.
* **Rejected** or **Metadata Rejected** — Apple found a problem; see Step 12.

Most reviews complete within about 24 to 48 hours (Apple states that the large majority are reviewed within 24 hours), though a first submission or a sensitive category can take longer. When approved, your app either goes live automatically or waits for you to release it, depending on the option you chose when submitting.

---

## Step 12: Handling the result — rejection vs. update (these are different!)
This is the part people most often get wrong, so read it carefully. **Fixing a rejected build and shipping an update to a live app are two different procedures.**

### If your build is REJECTED (before it has ever been released)
Your version has never gone public, so you do **not** create a new version. You fix the problem inside the *same* version:

* **If it is a Metadata Rejected** (a problem with your description, screenshots, or another store field, not the app itself): just fix the metadata and reply/resubmit in the Resolution Center. You often do **not** need a new build at all.
* **If it is a problem with the app itself:** fix your game, then rebuild with the **same marketing version** but a **higher build number**. Concretely, leave `build.product_version` at `1.0.0` and change `build.product_version_code` from `1` to `2`. Rebuild, and re upload the new `.ipa` with iTMSTransporter (remember to update the `bundle_version`, `size`, and `checksum` in `metadata.xml`, and increment `bundle_version` to `2`).
* Then, in App Store Connect, open the same `1.0.0` version, and in the Build section **remove the old build (number 1) and select the new one (number 2)**. Submit for review again.

Notice what stays fixed: the marketing version remains `1.0.0` the entire time you are trying to get your first release approved, because `1.0.0` was never actually released to the public. Only the build number climbs (1, 2, 3, ...) with each attempt. There is deliberately **no "create a new version" button available** in this situation, which confuses people. That button is only for updating an app that is already live, as described next.

### If your app is already LIVE and you want to ship an UPDATE
Now the flow is different. Your current version is public and finished, so you create a brand new version:

1. On your app's page in App Store Connect, click the **(+) Version or Platform** button. (This button is only available once your current version's status is **Ready for Distribution**, which is exactly why you never see it while a first release is still being reviewed or was rejected.)
2. Enter a **new, higher marketing version** number, for example `1.0.1` or `1.1.0`. You cannot reuse `1.0.0` because it was already released.
3. In NVGT, set `build.product_version` to that new number (for example `1.0.1`). You may reset `build.product_version_code` back to `1` for the new version, since build numbers only need to be unique within a marketing version.
4. Build, upload the new `.ipa` with iTMSTransporter (with a `metadata.xml` whose `bundle_short_version_string` is `1.0.1` and `bundle_version` is `1`), select the build in your new version, and submit for review.

### The two flows side by side
| Situation | Marketing version (`product_version`) | Build number (`product_version_code`) | Where in App Store Connect |
|---|---|---|---|
| First release keeps getting **rejected** | Stays the same (e.g. `1.0.0`) | **Increase** each try (1 → 2 → 3) | Same version; swap the build, resubmit. No "new version" button exists yet. |
| Shipping an **update** to a live app | **Increase** (e.g. `1.0.0` → `1.0.1`) | Reset to `1` (or keep climbing) | Use **(+) Version or Platform** to create a new version. |

Keep your three sources of version numbers in sync every single time: the values you build into the `.ipa` (`build.product_version` / `build.product_version_code`), the `bundle_short_version_string` / `bundle_version` in `metadata.xml`, and the version shown in App Store Connect. When they disagree, the upload or the submission fails.

---

## Selling in-app purchases
If your game sells items (coins, a premium unlock, extra levels, and so on) it uses NVGT's in-app purchase API, which is documented in the In-App Purchases reference. That reference covers the *code*; this section covers the *App Store side*: turning on payments, creating the products, and how Apple's purchase model differs from Google's (the difference is significant and is explained in both this tutorial and the Google Play one).

### Turn on payments first
Before you can create or sell any in-app purchase, the membership **Account Holder** must, in App Store Connect under **Business** (the "Agreements, Tax, and Banking" area):

* **Sign the Paid Applications Agreement**, and
* **Provide banking and tax information.**

The agreement must show as **Active**. This is required even to *test* purchases in Apple's sandbox, so do it early.

### The four product types — and you choose the type here
App Store Connect offers four in-app purchase types, and **you pick the type when you create the product.** The type is a fixed property of the product:

* **Consumable** — used once and then depleted, so it can be bought again (coins, extra lives, a hint pack). Consumables **cannot** be restored.
* **Non-Consumable** — bought once and owned forever (remove ads, unlock the full game). Non-consumables **can** be restored on a new device.
* **Auto-Renewable Subscription** — recurring access that renews automatically.
* **Non-Renewing Subscription** — access for a fixed period that does not auto-renew.

Most audio games use Consumable and Non-Consumable. The important idea for cross platform work: **on Apple, whether a product is consumable or non-consumable is decided right here in App Store Connect and enforced by the App Store's servers.**

### Create a product
1. In App Store Connect, open your app and, under **Monetization**, click **In-App Purchases**.
2. Click **+**, choose **Consumable** or **Non-Consumable**, and continue.
3. Set a **Reference Name** (internal only, up to 64 characters) and a **Product ID**. The Product ID is permanent: it cannot be edited after you save it, and it cannot be reused for another product even if you delete this one. **This Product ID is exactly the identifier your NVGT script passes to `iap_query_products()` and `iap_purchase_product()`, so the two must match.**
4. Set the **price**, add at least one **localized display name and description** (these are shown to customers), and upload a **review screenshot** clearly showing the item (used only by Apple's reviewers, never displayed on the store).

### How Apple's model affects your NVGT code
Because the App Store already knows each product's type from what you selected above, StoreKit finalizes a purchase with a single "finish" step that NVGT performs for you automatically. There is **no separate consume-versus-acknowledge action on iOS.** As a result, the `consume()` and `acknowledge()` methods on an `iap_purchase` **do nothing on iOS** — they are harmless no-ops that simply report success. You do not need them on Apple. You should still call the appropriate one in your script anyway (exactly as required for Android, described in the Google Play tutorial) so that the *same* code works correctly on both stores. Restoring behaves as expected: `iap_restore_purchases()` brings back non-consumables (and subscriptions), while consumables are never restored.

### Review
In-app purchases are reviewed by Apple. **Your first in-app purchase must be submitted together with an app version** (submit them in the same review). Once Apple has approved at least one purchase for your app, you can submit additional purchases on their own later without attaching them to a new app version.

---

## Quick reference checklist
1. `#pragma icon "icon.png"` — a real, opaque, square icon. (Mandatory.)
2. Enroll in the Apple Developer Program (99 USD/year).
3. OpenSSL on Windows: make `distribution.key`, a CSR, download the **Apple Distribution** `.cer`, and build `distribution.p12` with `-legacy` and a real password.
4. Register your **App ID** = your `build.product_identifier` (exact match).
5. Create and download an **App Store Connect** provisioning profile (`.mobileprovision`).
6. `#pragma ios_signing_identity`, `#pragma ios_signing_password`, `#pragma ios_provisioning_profile` → build a signed `.ipa`.
7. Add `#pragma microphone_usage_description` if you use the microphone.
8. Set `build.product_version` (e.g. `1.0.0`) and `build.product_version_code` (e.g. `1`).
9. Create the app in App Store Connect, note its numeric **Apple ID**, fill in all metadata (change the version from the default `1.0`).
10. Upload the build. Authenticate with an **app specific password** or, better, an **App Store Connect API key**. Then pick a method: **A** — build the `.itmsp` folder (`.ipa` + `metadata.xml` with matching versions, size, and MD5) and upload with `iTMSTransporter -f` (deprecated, retiring in 2026); **B** — write an `AppStoreInfo.plist` and upload with `iTMSTransporter -assetFile` (Apple's replacement); or **C** — run `ios-uploader` and skip Transporter entirely.
11. Optionally test via **TestFlight** (internal = no review; external = Beta App Review).
12. Submit for review. If rejected before release: same version, higher build number. Once live: new version via **(+) Version or Platform**.
13. Selling items? Sign the Paid Applications Agreement, create each product **choosing its type (Consumable/Non-Consumable)** in App Store Connect with a Product ID matching your script, and submit your first purchase alongside an app version. `consume()`/`acknowledge()` are no-ops on iOS.
