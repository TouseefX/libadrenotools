Forked Verison of libanderotools design to run on native Android apps

credits to Pipetto-crypto for fixes and patches

Credits To gamenative performance/WinNative source code for loading and some fixes

Credits To MrPurple for env loader

Tested with Roblox (Galaxy Store Verison) with Turniup MTR 3.0.0 AXxx S20 Ultra 5G (Vulkan)
different is high alot of fps boost it seems slow at frist but gets faster
I will release apk but roblox anti cheat flags it as tempering framework

Tested With Starlight (Among Us Mod Launcher) with Turniup MTR 3.2.0 AXxx S20 Ultra 5G (Freedeno Mode OPENGL GS With Fallback Qcom Gallatin)

This Launcher is known for lag so this was a good test and 60 fps felt like 120 fps? idk that is so werid to say
And It also fixes Graphical Bugs some of then not all this is still without the performance fix there is no cache so we will test again later

### Adreno Tools 
A library for applying rootless Adreno GPU driver modifications/replacements. Currently supports loading custom GPU drivers such as [turnip](https://docs.mesa3d.org/android.html#building-using-the-android-ndk),  enabling BCn textures and redirecting file operations to allow accessing shader dumps and modification of the [driver config file](https://gist.github.com/bylaws/04130932e2634d1c6a2a9729e3940d60) without root.

#### Documentation
API is documented in the `include/adrenotools` headers.

#### Support and Requirements
Android 12+
Arm64

Vulkan 1.3+

Snapdragon 865+

Please create an issue if support for anything else is desired.

Recommend [Drivers](https://github.com/TGMGT/Banners-Turnip)

And Freedeno Drivers

### FAQ

#### Is there an example project?

There is a simple bare-bones project [AdrenoToolsTest](https://github.com/darksylinc/AdrenoToolsTest) demonstrating how to get libadrenotools working.

#### How do I use this to update the drivers on my phone? Where's the apk?

You don't. This library is **not** for installing into Android and is **not** for end users.
This library is aimed at other developers.

Each individual app must explicitly make use of libadrenotools in order to load custom drivers into an app / game.

#### How do I use this library to make \<favourite game\> use newer drivers?

See previous question. It's up to the game developer to add support & use this library.

You could contact them to so they add support for it; but that's out of our power.

i don't know, if im allowed to put a patching guide here, but you can also do it on android without root
