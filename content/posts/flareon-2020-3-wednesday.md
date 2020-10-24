---
title: "Flare-On CTF 2020 Challenge 3: wednesday"
summary: "Unlike challenge 1, you probably won't be able to beat this game the old fashioned way."
date: 2020-09-18
categories:
  - "writeups"
tags:
  - "reversing"
---

## Challenge

> Be the wednesday.
> Unlike challenge 1, you probably won't be able to beat this game the old fashioned way.
> Read the README.txt file, it is very important.

## Observations

The provided program is a simple game that requires the player to either jump over or crouch under different lettered blocks.
The README states that only mydude.exe needs to be reversed and hints at the game rules with a diagram.
Experimenting with the game, it appears that the player must jump over any Sunday, Monday, or Tuesday blocks and crouch under any Thursday, Friday, or Saturday blocks otherwise the game will end.
In order to beat the game, we will probably need to reach a certain score that would be unattainable without cheating.

## Reversing the Program

The program is on the larger side but fortunately still contains useful symbol data.
A quick glance through the symbols leads us to `_winScene__eVaCVkG1QBiYVChMxpMGBQ`.
When the player successfully wins the game, the program uses this pointer to display the win scene.
It is possible to force the win scene to appear by manually putting the value of this pointer into `eip` in a debugger.
This will not display the flag however.

One of the cross references to this pointer comes from the `@update__Arw3f6ryHvqdibU49aaayOg@12` function.
Examining where it is used indicates how the win scene gets triggered by the game.

![score](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/wednesday/score.png)

The conditional branch before the call checks that the player's score is equal to 296.

Another interesting symbol is `_score__h34o6jaI3AO6iOQqLKaqhw`.
This is the location where the player's score is kept in memory.
Looking at the cross references, we can see that the score is incremented in the `onCollide` function.

![score_increment](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/wednesday/score_increment.PNG)

We can force the game to increment the score for every obstacle passed regardless of player movement by patching the conditional branch to always succeed.
Now we can hold down crouch and wait until our score reaches 296.

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/wednesday/flag.png)
