Forked Verison of libanderotools design to run on native Android apps

credits to Pipetto-crypto for fixes and patches

Credits To gamenative performance/WinNative source code for loading and some fixes

Credits To MrPurple for env loader

Screenshot of turniup and ite changing how UIs works btw

Turniup: https://snipboard.io/p67EwR.jpg

Normal: https://snipboard.io/H8rSxJ.jpg

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
add your libary to lib/arm64-v8a inside the apk and driver also

just start the libary by adding a code to the application class On Created or attach contex base part

rebuild the apk and sign it

but if the application does not have these you need to tell a dev to do it for you

but games can have anti tamping like roblox so it's impossible for these games
