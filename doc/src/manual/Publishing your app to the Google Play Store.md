# Publishing your app to the Google Play Store
This tutorial takes you from having no Google account at all to having your NVGT game live on the Google Play Store, and then updating it afterwards. Everything here can be done from **Windows** (or any platform NVGT builds on); unlike Apple's platform there is no equivalent of "you need a Mac", and NVGT builds and signs a complete, upload ready Android App Bundle for you.

If you have already read the "Publishing your app to the Apple App Store" tutorial, a lot of the shape here will feel familiar (register, sign, create a listing, upload, test, review, release), but **the details differ in important ways**, and a few of the differences bite hard if you carry Apple habits over. The most dangerous one is version numbering, which is called out prominently below. Read this guide fully before you start.

> Everything here was accurate against Google's documentation at the time of writing. Google changes the Play Console layout, wording, and policies frequently. When a screen does not match this text exactly, look for the control that does the same job; the underlying concepts are stable even when the interface moves.

## How Google Play differs from Apple at a glance
If you are coming from the Apple guide, internalize these differences first, because they change how you plan your release:

* **Fee:** Google charges a **one time 25 USD** registration fee, forever, versus Apple's 99 USD every year.
* **No Mac, no per build certificates dance.** NVGT signs your Android build with a normal Java keystore, and you can even let NVGT generate that keystore automatically.
* **The upload format is an Android App Bundle (`.aab`), not an installable file.** Google builds the actual per device APKs from your bundle on its servers.
* **Version numbers behave differently, and this is the big trap.** On Google Play the internal build number (`versionCode`) is a single integer that must **always increase across the entire life of your app and can never be reused or reset**. This is *not* like Apple, where the build number can restart at 1 whenever the marketing version changes. There is a whole section on this below; do not skim it.
* **New personal accounts must run a real closed test before they can publish.** If your Play Console account is personal and was created after 13 November 2023, Google requires you to run a closed test with **at least 12 testers for 14 continuous days** before it will let you release to the public. Plan for this; it adds two weeks to your first launch.
* **There is no "create a version record then attach a build" step.** On Google Play you simply upload a bundle with a higher `versionCode` and start a release. There is no pre made version object like Apple's.

## Overview: the whole journey
1. **Create an app icon** with `#pragma icon` (used for the on device launcher icon), and separately prepare a 512x512 store icon for the listing.
2. **Register a Google Play Console developer account** (25 USD, one time).
3. **Configure signing.** Let NVGT generate (or point it at) a keystore, and understand Play App Signing.
4. **Set your package name** (`product_identifier`) and **build an `.aab`** by setting `build.android_format = aab`.
5. **Understand version numbers** (`versionCode` must always increase; `versionName` is what users see).
6. **Create your app in Play Console** and complete every "App content" declaration (data safety, content rating, target audience, privacy policy, and so on) plus the store listing (icon, feature graphic, screenshots, descriptions).
7. **Run a closed test** (mandatory for new personal accounts: 12 testers, 14 days) and, when eligible, **apply for production access**.
8. **Upload your `.aab` and create a release**, then roll it out for review.
9. **Handle review and updates:** to update, just build with a higher `versionCode`, upload, and create a new production release.

---

## Step 1: App icons (there are two of them on Android)
Android splits the icon into two separate things, and you need both:

* **The launcher icon** that appears on the device home screen and app list. This lives inside your built app, and NVGT sets it from your script:

  ```
  #pragma icon "icon.png"
  ```

  Point it at a square PNG (a large source such as 512x512 or 1024x1024 is recommended so it scales cleanly). See the "compiling your project for distribution" tutorial for the full per platform behavior.

  **Important:** if you omit `#pragma icon`, NVGT does *not* leave the launcher icon blank — it ships **SDL's default icon**. This is a leftover from the SDL Android project template that NVGT's Android build is based on: the project tree was taken from SDL and its stock `ic_launcher` images were left in place, so the fallback is a generic image that has nothing to do with your game. Google Play **rejects** apps whose icon does not represent the app, so submitting with the SDL default icon will get your app refused. Always set your own `#pragma icon`. (This fallback is also inconsistent with iOS, where omitting the pragma instead produces no icon at all rather than a default one.)

* **The Play Store listing icon**, a **512 x 512 px, 32 bit PNG, at most 1 MB**, that you upload separately in the Play Console store listing (Step 6). This is the icon people see on your store page, and it is required to publish. It is a distinct upload from the launcher icon above, so prepare a clean 512x512 version of your artwork.

Unlike Apple, where the store icon travels inside the uploaded build, on Google Play the 512x512 store icon is entered in the web console, not baked into the bundle.

> **Critical: the two icons must be the same image.** Because the launcher icon lives in your build and the 512x512 store icon is uploaded separately, it is easy for them to end up different, and Google Play **rejects** apps when they do. This is enforced under the **Misleading Claims** policy: "App does not match the store listing — when it's installed, your app's icon or name is different to the one shown in its store listing." A very common way to trigger this with NVGT is to forget `#pragma icon` (so the app installs with **SDL's default launcher icon**, see the warning above) while uploading your own custom artwork as the 512x512 store icon — the on device icon and the store icon then disagree and the submission is refused. Always set `#pragma icon` to your real artwork *and* upload that same artwork (resized to 512x512) as the store icon, so the icon a user sees after installing is identical to the one on your store page. The same applies to the app name: the installed app's name and the store listing name should match.

---

## Step 2: Register a Google Play Console developer account
Go to the [Google Play Console](https://play.google.com/console) and register.

* **Cost:** a **one time 25 USD** registration fee (not annual). You pay it once, ever, for the account.
* **Prerequisite:** a Google account. You must be at least 18 years old.

### Personal vs. Organization
* **Personal account.** For an individual hobbyist or developer. **No D-U-N-S Number required.** This is the simplest option and almost certainly what you want as a solo developer, but note the mandatory closed testing requirement below.
* **Organization account.** For a company or other entity. Requires a free **D-U-N-S Number** (which can take a while to obtain from Dun & Bradstreet, so start early) and a website. An organization account is *required* for certain categories such as financial or government apps.

### Identity verification
As part of registration you provide and verify your legal name, address, contact email, and phone number. Email and phone are verified by one time codes. Depending on your country and whether your Google payments profile is already verified, you may also need to verify your identity with a **government issued photo ID**. Google says verification "may take a few days".

### The mandatory closed test for new personal accounts (very important)
This has no Apple equivalent and catches many first time publishers by surprise:

> If your account is a **personal** developer account **created after 13 November 2023**, you must run a **closed test** with **at least 12 testers** who have been **opted in continuously for at least 14 days** before Google will let you **apply for production access** and publish to the store.

The 14 days must be *consecutive* for the same testers; if a tester opts out and back in, the streak does not simply add up. Practically, this means your very first launch has a built in two week minimum lead time during which you must keep at least 12 real people opted into your closed test. Line up those testers early (friends, a community, a mailing list). This is covered again in Step 7 where the testing tracks are explained.

Organization accounts are exempt from this specific requirement.

Once registered and verified, you use one website for everything: the **[Google Play Console](https://play.google.com/console)**.

---

## Step 3: Signing and Play App Signing
Every Android app must be cryptographically signed. NVGT handles the actual signing for you, but you should understand the model Google uses so you keep the right file safe.

### The two key model (Play App Signing)
Google Play uses a system called **Play App Signing**, which is **required for new apps**. It involves two different keys:

* **The app signing key.** The key that signs the APKs actually delivered to users' devices. **Google holds and protects this key for you.** It never changes for the life of your app.
* **The upload key.** The key *you* use to sign the bundle you upload. Google verifies your upload with it, then re signs the app for users with the app signing key.

The recommended and simplest path: let Google manage the app signing key (this is the default), and **the key you sign your first upload with automatically becomes your upload key.** You then reuse that same key for every future upload.

Why this design is good for you: if you ever lose your **upload** key, it is **recoverable**, you can request an upload key reset in the Play Console. If Google manages the **app signing** key, you can never lose it. (If you insisted on managing the app signing key yourself and lost it, you could never update your app again, which is exactly why Google's managed option is recommended.)

### How NVGT signs your Android build
NVGT signs your `.aab` with a standard Java keystore. By default, if you do not specify one, NVGT automatically generates a keystore (RSA 2048, valid for about 27 years, which satisfies Google's requirement that the key remain valid past October 2033) and stores it in your home directory. The relevant configuration keys are:

* `build.android_signature_cert` — path to the keystore file (default: `.nvgt_android.keystore` in your home directory).
* `build.android_signature_password` — the keystore password (default: `pass:android`).
* `build.android_signature_info` — the certificate's distinguished name (default: `cn=NVGT`).

**For a real app you intend to publish and maintain, do not rely on the throwaway defaults.** Set an explicit keystore path and a strong password of your own, for example:

```
#pragma config build.android_signature_cert = mygame-upload.keystore
#pragma config build.android_signature_password = pass:YOUR_STRONG_PASSWORD
```

Then, critically:

* **Keep that keystore file and its password safe, backed up, and unchanged.** It is your upload key. Every future update to your app must be signed with the *same* keystore. If you regenerate a different keystore later, uploads will be rejected until you go through Google's upload key reset process.
* Because Google manages the app signing key, a lost *upload* key is a recoverable inconvenience rather than a catastrophe, but it is still far easier to just keep the file safe from the start.

The password format `pass:YOUR_PASSWORD` is passed through to the Java signing tools; the `pass:` prefix means "the literal password follows".

---

## Step 4: Set your package name and build an App Bundle
### Package name (application ID)
Your app's package name is the same value NVGT calls the **product identifier**, in reverse domain form. Set it:

```
#pragma config build.product_identifier = com.yourcompany.yourgame
```

On Android this identifier is especially important: it is baked into filesystem paths and is the permanent, unique identity of your app on the Play Store. Once you publish with it you can never change or reuse it, so choose carefully.

### Build an `.aab`, not an `.apk`
Google Play requires new apps to be uploaded as an **Android App Bundle (`.aab`)**. An `.aab` is a publishing format only; it cannot be installed directly on a device. Google Play processes it and generates the optimized APKs that get delivered to each user's device.

Tell NVGT to produce a bundle:

```
#pragma config build.android_format = aab
```

(The default is `apk`, which is great for testing and side loading but is not what you upload to Google Play for a new app.) NVGT generates and signs the `.aab` for you without requiring Google's `bundletool` to be installed. Everything else about the build (icon, permissions, identifier, signing) is identical between the two formats, so you can keep an `apk` build for local testing and switch to `aab` when preparing a store upload.

Compile for Android to get your signed `mygame.aab`.

---

## Step 5: Version numbers — read this carefully (it is not like Apple)
Android has two version values, and NVGT exposes both:

* **`build.product_version`** → Android's **`versionName`**. This is the **user visible** version string shown on the store, such as `1.0.0`. It is free form; you can use any string, though `major.minor.patch` is conventional.
* **`build.product_version_code`** → Android's **`versionCode`**. This is an **internal positive integer** that users never see. It is how Google Play decides which upload is newer.

### The rule that trips up Apple developers
On Google Play, **`versionCode` must strictly increase with every single upload, across the entire lifetime of the app, and a value once used can never be reused.** Google's own words: *"You can't upload an APK to the Play Store with a versionCode you have already used for a previous version."*

This is **fundamentally different from Apple.** On Apple you can reset the build number back to 1 whenever the marketing version increases. **On Google Play you can never reset it.** The `versionCode` just keeps climbing forever: 1, 2, 3, ... no matter what `versionName` does. Whether you are releasing version `1.0.0` or `5.2.7`, the very next upload must simply have a `versionCode` higher than any bundle you have ever uploaded before (including bundles you only sent to a test track).

So the correct mental model is:

* `versionName` (`product_version`): whatever you want users to see, for example `1.0`, then `1.0.1`, then `2.0`.
* `versionCode` (`product_version_code`): a monotonic counter that only ever goes up and is never reset.

### How NVGT handles this by default
NVGT's default for `build.product_version_code` on Android is the current Unix timestamp in seconds divided by 60. Because that value is always larger the next time you build, **the default automatically guarantees an ever increasing `versionCode`**, and you generally do not need to manage it by hand at all.

If you *do* choose to set `product_version_code` manually (for example to get clean sequential numbers 1, 2, 3), then it becomes your responsibility to **always raise it and never reuse or lower a value** you have already uploaded. If you are going to hand manage it, the safest approach is to also make sure it is always higher than the timestamp based numbers any previous default build might have produced, or to pick manual management from your very first upload and never look back. When in doubt, leave the default alone and let it climb on its own.

For clarity, set your user facing version explicitly and let the code auto increment:

```
#pragma config build.product_version = 1.0.0
// product_version_code left at its auto-increasing default
```

---

## Step 6: Create your app in Play Console and complete every required section
### Create the app
1. In the [Play Console](https://play.google.com/console), go to **All apps** and click **Create app**.
2. Fill in:
   * **App name** (up to 30 characters; shown on the store).
   * **Default language.**
   * **App or game.**
   * **Free or paid.** Note a one way restriction: you can switch a paid app to free later, but you **cannot switch a free app to paid** after it has been published. Decide deliberately.
   * The required **declarations** (Developer Program Policies and US export law checkboxes).
3. Click **Create app**.

### Complete the "App content" declarations
Google will not let you publish until every required item is done. In the Play Console, under **Policy** (or "Policy and programs") **> App content**, complete all of these:

* **Privacy policy:** a working URL to your privacy policy. Required in practice for essentially all apps (and required to complete the Data safety form).
* **App access:** declare whether everything in your app is usable without a login. If parts require sign in, you must provide working **test credentials** so Google's reviewers can get in.
* **Ads:** declare whether your app contains ads.
* **Content ratings:** complete the **IARC** questionnaire. This assigns official age ratings (ESRB, PEGI, and so on). It is required; an unrated app can be removed, and misrepresenting content can get you suspended.
* **Target audience and content:** declare the age group(s) your app targets (the bands range from "5 and under" up to "18 and over"). Apps that include children in the audience must meet Google's Families policy.
* **Data safety:** required for all apps. You declare exactly what user data your app collects or shares (including data collected by any third party libraries), why, whether it is encrypted in transit, and whether users can request deletion. **Your answers must match what your app actually does and what your privacy policy says;** inconsistencies are a common cause of rejection or later enforcement.
* **Government apps** declaration (every developer must state whether the app is a government app).
* **Financial features** declaration (every developer must complete this, even if only to certify "none").
* Plus any conditional ones that apply to you (news apps, health apps, sensitive permissions, and so on).

### Fill in the store listing
Under **Grow** (or "Store presence") **> Main store listing**, provide:

* **App icon:** 512 x 512 px, 32 bit PNG, max 1 MB (the store icon from Step 1). This must be the **same artwork as your on device launcher icon** (`#pragma icon`); if they differ, Google Play rejects the app under the Misleading Claims policy (see the warning in Step 1).
* **Feature graphic:** **1024 x 500 px**, JPEG or 24 bit PNG **with no alpha/transparency**. This is **required**, and it is the banner shown at the top of your store page.
* **Phone screenshots:** at least **2** (up to 8). JPEG or 24 bit PNG. Each side must be between **320 px and 3840 px**, and the longer side may be at most twice the shorter side. For the best presentation use a 16:9 (landscape) or 9:16 (portrait) ratio.
* **Short description:** up to **80 characters**.
* **Full description:** up to **4000 characters**.
* App **category** and **contact details** (email is required).

### Pricing and countries
Under the pricing/availability settings, set the app free or paid and choose which countries and regions it is distributed to. Country targeting is based on the country registered to each user's Google account, not their physical location.

---

## Step 7: Testing tracks and (for new personal accounts) the mandatory closed test
Google Play offers four **release tracks**, each aimed at a wider audience than the last:

* **Internal testing:** the fastest track, for up to **100 testers** you list by email. Builds reach testers almost immediately with minimal processing. Great for your own quick QA.
* **Closed testing:** a larger controlled group invited via email lists or Google Groups. **This is the track you use to satisfy the new personal account requirement** (12 testers, 14 days).
* **Open testing:** a public beta anyone can join via a link (you can cap the number, minimum 1,000, or leave it unlimited).
* **Production:** the full public release on the store.

### The mandatory closed test (new personal accounts)
If your account is personal and was created after 13 November 2023, before you can release to **Production** you must:

1. Create a **closed testing** release and get **at least 12 testers** opted in.
2. Keep those testers opted in **continuously for at least 14 days**.
3. Then go to the Play Console **Dashboard** and **apply for production access**, answering questions about your test, your app, and your production readiness. Google reviews this application (usually within about 7 days, sometimes longer).

Only after that application is approved can your app go to Production. So even a finished, working game cannot skip the two week closed test if your account is subject to this rule. Set your testers up as early as possible.

---

## Step 8: Create a release and roll it out
Whether you are publishing a closed test, an open test, or a production release, the mechanics are the same:

1. In the Play Console, open the track you want under **Test and release** (Internal testing, Closed testing, Open testing) or **Production**.
2. Click **Create new release**.
3. If this is your first ever release, confirm the **Play App Signing** setup (the default, letting Google manage the app signing key, is recommended).
4. **Upload your `.aab`.** After upload it becomes part of your app's bundle library.
5. Give the release a **name** (often just the version) and write **release notes** (up to 500 characters per language).
6. Click **Next**/**Save**, resolve any errors or warnings on the review screen, then **roll out** the release.

For a **production** release you also choose a **rollout percentage** (a staged rollout), so the update reaches, say, 10% of users first; you can then increase the percentage over time or halt it if something is wrong.

### Send your changes for review (the Publishing overview page)
Creating or rolling out a release is very often **not** the final action, and this trips people up constantly. Google Play collects your pending changes — new releases, store listing edits, the App content declarations, pricing, and so on — and holds them until you explicitly submit them all from one place: the **Publishing overview** page. Select your app, then choose **Publishing overview** at the top of the left menu.

* When you finish a release you are offered a choice: **publish/roll out immediately**, or **save** the changes, which adds them to the **"Changes ready to send for review"** section on the Publishing overview page.
* Store listing edits, App content answers, and pricing changes are always gathered there and require an explicit submit.

On the **Publishing overview** page, click **Send for review** (the button may show the number of pending changes, for example "Send 3 changes for review"). **Nothing is actually submitted to Google, and nothing will ever go live, until you do this.** This is also where you return after a rejection: fix the issue, come back to the Publishing overview page, and **Send for review** again. This is exactly what Google's rejection emails mean when they tell you to "send changes to your app for review on the Publishing overview page".

**Managed publishing (optional):** by default, once Google approves your changes they go live automatically. If you turn on **Managed publishing** (a toggle on the Publishing overview page), approved changes instead wait in a **"Changes ready to publish"** section until you click **Publish changes**, letting you pick the exact go-live moment (handy for coordinating a launch). Leave it off if you simply want approved updates to release as soon as they pass review.

### Review and timing
Google reviews submissions before they go live. This used to be near instant, but current guidance is to **plan for up to 7 days**, and possibly longer for brand new apps or new developer accounts. You will get an email when review completes.

---

## Step 9: Target API level requirement
Google Play requires apps to **target a recent Android API level** to be published or updated, and the required level advances every year (for example, from 31 August 2025 new apps and updates were required to target Android 15 / API level 35 or higher). NVGT builds against a current API level for you, so this is normally handled automatically, but be aware that an older NVGT toolchain may eventually be unable to publish updates until it is brought up to the then current target level. If an upload is rejected specifically for targeting too old an API level, update your NVGT toolchain and rebuild.

---

## Step 10: Updating your app (much simpler than Apple)
Once your app is live, shipping an update is straightforward and does not involve creating any "version record":

1. Increase the version. Bump `build.product_version` (`versionName`) to whatever users should see, for example `1.0.1`. Ensure `versionCode` (`product_version_code`) is **higher than any bundle you have ever uploaded** (NVGT's default handles this automatically; if you manage it manually, raise it).
2. Rebuild your `.aab`, signed with the **same keystore** as before.
3. In the Play Console, go to **Production**, click **Create new release**, upload the new `.aab`, add release notes, and roll out (optionally as a staged percentage rollout).
4. Go to the **Publishing overview** page and click **Send for review** to actually submit the update (see Step 8) — the release is not submitted until you do this.

That is the entire update flow. Because Google Play keys everything off the ever increasing `versionCode`, there is no separate versioning ceremony: a higher `versionCode` simply *is* a newer version. Contrast this with Apple, where an update requires explicitly creating a new marketing version record before you can attach a build.

---

## Selling in-app purchases
If your game sells items it uses NVGT's in-app purchase API, documented in the In-App Purchases reference. That reference covers the *code*; this section covers the *Google Play side*, and one very important way Google's model is the **opposite** of Apple's.

### Turn on payments first
To sell anything you must set up a **Google Play payments (merchant) profile** in the Google Payments Center and link it to your developer account. You also need a signed build uploaded to a track (NVGT builds the Play Billing support into your app for you). Purchases only function once your app has been published/approved, though you can test them earlier with license testers (below).

### Create a product
1. In the Play Console, open your app and go to **Monetize with Play > Products > One-time products** (subscriptions are on a separate page).
2. Click **Create** (a one-time product).
3. Set a **Product ID** — it is permanent and **cannot be changed or reused** once created. **This Product ID is exactly the identifier your NVGT script passes to `iap_query_products()` and `iap_purchase_product()`, so the two must match.**
4. Set the name, description, and price, then **Activate** the product.

### The key difference from Apple: consumable vs. non-consumable is decided in CODE, not the console
This is the single most important thing to understand here, and it is the reverse of Apple. **Google Play has no consumable/non-consumable setting.** A one-time product is simply a one-time product. What makes a purchase behave as consumable or non-consumable is entirely what your NVGT script does after the purchase succeeds:

* Call the purchase's **`consume()`** → the item is used up and the product can be **bought again** → it behaves as a **consumable** (coins, gems, a hint pack).
* Call the purchase's **`acknowledge()`** (and do *not* consume it) → the product becomes a **permanent entitlement** owned by the account → it behaves as a **non-consumable** (remove ads, unlock premium).

So on Google Play the exact same product could be a consumable or a non-consumable depending only on which method your code calls. (Contrast this with Apple, where you choose Consumable or Non-Consumable in App Store Connect and the calls do nothing.)

### You MUST finalize within 3 days, or Google refunds it
On Google Play, finalizing is not optional. **Every purchase must be consumed or acknowledged within 3 days (72 hours), or Google Play automatically refunds it and revokes the item from the user.** Consuming a purchase also satisfies the acknowledgement requirement (so you never do both on the same purchase). Therefore, after you grant the item on `IAP_PURCHASE_SUCCESS` (or `IAP_PURCHASE_RESTORED`), promptly call `consume()` for a consumable or `acknowledge()` for a non-consumable. This is exactly why these calls have a real, mandatory effect on Android, whereas on iOS they are harmless no-ops — so writing your code to always call the right one is correct for both stores.

Non-consumable entitlements are recovered automatically by NVGT when you query or restore purchases; consumables are not "restored" (once consumed, they are simply available to buy again).

### Testing and review
You can test purchases without being charged real money by adding yourself and others as **license testers** in the Play Console (**Settings > License testing**); license testers' purchases are free. Individual products are not reviewed separately — Google reviews the app — but as noted, purchases only work once the app itself is published.

---

## Quick reference checklist
1. `#pragma icon "icon.png"` for the launcher icon, and upload the **same artwork** (resized to **512x512**) as the store icon — they must match, or Google rejects the app under the Misleading Claims policy. (Omitting `#pragma icon` ships SDL's default icon, which causes the same rejection.)
2. Register a **Play Console** account (**25 USD one time**). New personal accounts: line up **12 testers** for a **14 day** closed test.
3. Signing: set an explicit `build.android_signature_cert` + `build.android_signature_password`, and **back up that keystore** (it is your upload key, reused for every update).
4. Set `build.product_identifier` (your permanent package name) and `build.android_format = aab`.
5. Versions: `build.product_version` is the user visible `versionName`; `build.product_version_code` is `versionCode` and **must always increase and never be reused or reset** (the default auto increments, so usually leave it alone).
6. Create the app in Play Console; complete **all** App content declarations (privacy policy, app access, ads, content rating, target audience, **data safety**, government/financial declarations) and the store listing (**512x512 icon**, **1024x500 feature graphic**, **2+ screenshots**, short/full descriptions).
7. New personal accounts: run the **closed test (12 testers / 14 days)**, then **apply for production access**.
8. **Create a release**, upload the `.aab`, roll out, then go to the **Publishing overview** page and click **Send for review** (nothing is submitted until you do). Plan for **up to 7 days** of review. After a rejection, fix the issue and Send for review again from the same page.
9. To update: raise `versionName`, keep `versionCode` climbing, sign with the **same keystore**, upload a new production release.
10. Selling items? Set up a payments profile, create one-time products (Product ID matching your script). There is **no consumable/non-consumable setting** — your code decides: `consume()` = consumable, `acknowledge()` = non-consumable, and you **must** call one within 3 days or Google refunds the purchase.
