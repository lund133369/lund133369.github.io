---
title: Fast install terminal kitty-zsh-polybar-rofi-bspwm
description: "Fast install terminal kitty-zsh-POWERLVL10k"
published: true
pubDate: "2024-06-01"
heroImage: /assets/posts1/entorno/zsh_kitty_polybar_rofi_bspwm.gif
---


- script para tener listo la kitty-zsh-powerlvl10k

	```console
	user@pc:~$ sudo apt -y install python3 git kitty zsh 
	user@pc:~$ chsh -s /bin/zsh $(whoami) && sudo chsh -s /bin/zsh root
	user@pc:~$ git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/powerlevel10k
	user@pc:~$ echo 'source ~/powerlevel10k/powerlevel10k.zsh-theme' >>~/.zshrc
	user@pc:~$ zsh
	```

<span>
<i class="fa fa-copy"></i>
</span>
