Forked Verison of libanderotools design to run on native Android apps

credits to Pipetto-crypto for fixes and patches

Credits To gamenative performance/WinNative source code for loading and some fixes

Credits To MrPurple for env loader

Tested with Roblox with Turniup MTR 3.2.0 AXxx S20 Note Ultra 5G (Vulkan)

tested with games like Frontline and jump showdown ping is more less then before and fps is better with screen tearing issues 

Tested with Roblox with Turniup MTR 3.2.0 AXxx S20 Ultra 5G (And Note) (Vulkan)

unlike the note verison this one was at maximum and has better performance but it got so hot the charging stopped working
this phone used to be a cry baby when I play jump showdown now its not lol

Tested with Roblox with Turniup MrPurple T24 AXxx S20 Ultra 5G (Vulkan)
what did bro feed this driver its too fast and no overheating prob because Snapdragon 865 is balanced 

### Adreno Tools 
A library for applying rootless Adreno GPU driver modifications/replacements. Currently supports loading custom GPU drivers such as [turnip](https://docs.mesa3d.org/android.html#building-using-the-android-ndk),  enabling BCn textures and redirecting file operations to allow accessing shader dumps and modification of the [driver config file](https://gist.github.com/bylaws/04130932e2634d1c6a2a9729e3940d60) without root.

#### Documentation
API is documented in the `include/adrenotools` headers.

#### Support and Requirements
Android 12+
Arm64

Vulkan 1.3+

Adero 650+

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

but most games use opengl es but unitly games do have vulkan but not used you can just use Google ANGLE I do not recommend using Zink for this
