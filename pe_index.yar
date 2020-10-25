/*
Generated by YARA_Rules_Util
On 2020-10-23
*/
include "./cve_rules/pe/CVE-2010-0805_pe.yar"
include "./cve_rules/pe/CVE-2015-1701_pe.yar"
include "./cve_rules/pe/CVE-2015-2426_pe.yar"
include "./cve_rules/pe/CVE-2015-2545_pe.yar"
include "./maldocs/pe/Maldoc_Dridex_pe.yar"
include "./malware/Operation_Blockbuster/pe/cert_wiper_pe.yar"
include "./malware/Operation_Blockbuster/pe/DeltaCharlie_pe.yar"
include "./malware/Operation_Blockbuster/pe/general_pe.yar"
include "./malware/Operation_Blockbuster/pe/HotelAlfa_pe.yar"
include "./malware/Operation_Blockbuster/pe/IndiaBravo_pe.yar"
include "./malware/Operation_Blockbuster/pe/IndiaDelta_pe.yar"
include "./malware/Operation_Blockbuster/pe/IndiaEcho_pe.yar"
include "./malware/Operation_Blockbuster/pe/IndiaGolf_pe.yar"
include "./malware/Operation_Blockbuster/pe/IndiaHotel_pe.yar"
include "./malware/Operation_Blockbuster/pe/IndiaJuliett_pe.yar"
include "./malware/Operation_Blockbuster/pe/IndiaWhiskey_pe.yar"
include "./malware/Operation_Blockbuster/pe/KiloAlfa_pe.yar"
include "./malware/Operation_Blockbuster/pe/LimaAlfa_pe.yar"
include "./malware/Operation_Blockbuster/pe/LimaBravo_pe.yar"
include "./malware/Operation_Blockbuster/pe/LimaCharlie_pe.yar"
include "./malware/Operation_Blockbuster/pe/LimaDelta_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoAlfa_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoBravo_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoCharlie_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoDelta_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoEcho_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoFoxtrot_mod_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoGolf_mod_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoHotel_pe.yar"
include "./malware/Operation_Blockbuster/pe/RomeoWhiskey_pe.yar"
include "./malware/Operation_Blockbuster/pe/sharedcode_pe.yar"
include "./malware/Operation_Blockbuster/pe/SierraAlfa_pe.yar"
include "./malware/Operation_Blockbuster/pe/SierraBravo_pe.yar"
include "./malware/Operation_Blockbuster/pe/SierraCharlie_pe.yar"
include "./malware/Operation_Blockbuster/pe/SierraJuliettMikeOne_pe.yar"
include "./malware/Operation_Blockbuster/pe/SierraJuliettMikeTwo_pe.yar"
include "./malware/Operation_Blockbuster/pe/TangoBravo_pe.yar"
include "./malware/Operation_Blockbuster/pe/UniformAlfa_pe.yar"
include "./malware/Operation_Blockbuster/pe/WhiskeyAlfa_pe.yar"
include "./malware/Operation_Blockbuster/pe/WhiskeyBravo_mod_pe.yar"
include "./malware/Operation_Blockbuster/pe/WhiskeyCharlie_pe.yar"
include "./malware/Operation_Blockbuster/pe/WhiskeyDelta_pe.yar"
include "./malware/pe/APT_APT10_pe.yar"
include "./malware/pe/APT_APT15_pe.yar"
include "./malware/pe/APT_APT17_pe.yar"
include "./malware/pe/APT_APT1_pe.yar"
include "./malware/pe/APT_APT29_Grizzly_Steppe_pe.yar"
include "./malware/pe/APT_APT3102_pe.yar"
include "./malware/pe/APT_APT9002_pe.yar"
include "./malware/pe/APT_Backspace_pe.yar"
include "./malware/pe/APT_Bestia_pe.yar"
include "./malware/pe/APT_Blackenergy_pe.yar"
include "./malware/pe/APT_Bluetermite_Emdivi_pe.yar"
include "./malware/pe/APT_C16_pe.yar"
include "./malware/pe/APT_Carbanak_pe.yar"
include "./malware/pe/APT_Careto_pe.yar"
include "./malware/pe/APT_Casper_pe.yar"
include "./malware/pe/APT_CheshireCat_pe.yar"
include "./malware/pe/APT_Cloudduke_pe.yar"
include "./malware/pe/APT_Codoso_pe.yar"
include "./malware/pe/APT_CrashOverride_pe.yar"
include "./malware/pe/APT_DeepPanda_Anthem_pe.yar"
include "./malware/pe/APT_DeputyDog_pe.yar"
include "./malware/pe/APT_Derusbi_pe.yar"
include "./malware/pe/APT_DPRK_ROKRAT_pe.yar"
include "./malware/pe/APT_Dubnium_pe.yar"
include "./malware/pe/APT_Duqu2_pe.yar"
include "./malware/pe/APT_Emissary_pe.yar"
include "./malware/pe/APT_eqgrp_apr17_pe.yar"
include "./malware/pe/APT_EQUATIONGRP_pe.yar"
include "./malware/pe/APT_Equation_pe.yar"
include "./malware/pe/APT_fancybear_dnc_pe.yar"
include "./malware/pe/APT_FiveEyes_pe.yar"
include "./malware/pe/APT_furtim_pe.yar"
include "./malware/pe/APT_FVEY_ShadowBrokers_Jan17_Screen_Strings_pe.yar"
include "./malware/pe/APT_Grasshopper_pe.yar"
include "./malware/pe/APT_Greenbug_pe.yar"
include "./malware/pe/APT_Grizzlybear_uscert_pe.yar"
include "./malware/pe/APT_HackingTeam_pe.yar"
include "./malware/pe/APT_Hellsing_pe.yar"
include "./malware/pe/APT_HiddenCobra_pe.yar"
include "./malware/pe/APT_Hikit_pe.yar"
include "./malware/pe/APT_Industroyer_pe.yar"
include "./malware/pe/APT_Irontiger_pe.yar"
include "./malware/pe/APT_Kaba_pe.yar"
include "./malware/pe/APT_Ke3Chang_TidePool_pe.yar"
include "./malware/pe/APT_KeyBoy_pe.yar"
include "./malware/pe/APT_LotusBlossom_pe.yar"
include "./malware/pe/APT_Minidionis_pe.yar"
include "./malware/pe/APT_Mirage_pe.yar"
include "./malware/pe/APT_Molerats_pe.yar"
include "./malware/pe/APT_Mongall_pe.yar"
include "./malware/pe/APT_NGO_pe.yar"
include "./malware/pe/APT_OpClandestineWolf_pe.yar"
include "./malware/pe/APT_OPCleaver_pe.yar"
include "./malware/pe/APT_OpDustStorm_pe.yar"
include "./malware/pe/APT_OpPotao_pe.yar"
include "./malware/pe/APT_Passcv_pe.yar"
include "./malware/pe/APT_PCclient_pe.yar"
include "./malware/pe/APT_Pipcreat_pe.yar"
include "./malware/pe/APT_Platinum_pe.yar"
include "./malware/pe/APT_Poseidon_Group_pe.yar"
include "./malware/pe/APT_Prikormka_pe.yar"
include "./malware/pe/APT_PutterPanda_pe.yar"
include "./malware/pe/APT_RedLeaves_pe.yar"
include "./malware/pe/APT_Regin_pe.yar"
include "./malware/pe/APT_RemSec_pe.yar"
include "./malware/pe/APT_Sauron_extras_pe.yar"
include "./malware/pe/APT_Sauron_pe.yar"
include "./malware/pe/APT_Scarab_Scieron_pe.yar"
include "./malware/pe/APT_Seaduke_pe.yar"
include "./malware/pe/APT_Shamoon_StoneDrill_pe.yar"
include "./malware/pe/APT_Snowglobe_Babar_pe.yar"
include "./malware/pe/APT_Sofacy_Bundestag_pe.yar"
include "./malware/pe/APT_Sofacy_Jun16_pe.yar"
include "./malware/pe/APT_Sphinx_Moth_pe.yar"
include "./malware/pe/APT_Stuxnet_pe.yar"
include "./malware/pe/APT_Terracota_pe.yar"
include "./malware/pe/APT_ThreatGroup3390_pe.yar"
include "./malware/pe/APT_Turla_Neuron_pe.yar"
include "./malware/pe/APT_Turla_RUAG_pe.yar"
include "./malware/pe/APT_Unit78020_pe.yar"
include "./malware/pe/APT_UP007_SLServer_pe.yar"
include "./malware/pe/APT_Uppercut_pe.yar"
include "./malware/pe/APT_Waterbug_pe.yar"
include "./malware/pe/APT_WildNeutron_pe.yar"
include "./malware/pe/APT_Winnti_pe.yar"
include "./malware/pe/APT_WoolenGoldfish_pe.yar"
include "./malware/pe/MALW_AgentTesla_pe.yar"
include "./malware/pe/MALW_Alina_pe.yar"
include "./malware/pe/MALW_Andromeda_pe.yar"
include "./malware/pe/MALW_Arkei_pe.yar"
include "./malware/pe/MALW_Athena_pe.yar"
include "./malware/pe/MALW_Atmos_pe.yar"
include "./malware/pe/MALW_ATMPot_pe.yar"
include "./malware/pe/MALW_ATM_HelloWorld_pe.yar"
include "./malware/pe/MALW_AZORULT_pe.yar"
include "./malware/pe/MALW_Backoff_pe.yar"
include "./malware/pe/MALW_Bangat_pe.yar"
include "./malware/pe/MALW_Batel_pe.yar"
include "./malware/pe/MALW_BlackRev_pe.yar"
include "./malware/pe/MALW_Boouset_pe.yar"
include "./malware/pe/MALW_Bublik_pe.yar"
include "./malware/pe/MALW_Buzus_Softpulse_pe.yar"
include "./malware/pe/MALW_CAP_HookExKeylogger_pe.yar"
include "./malware/pe/MALW_Chicken_pe.yar"
include "./malware/pe/MALW_Citadel_pe.yar"
include "./malware/pe/MALW_Cookies_pe.yar"
include "./malware/pe/MALW_Corkow_pe.yar"
include "./malware/pe/MALW_Cxpid_pe.yar"
include "./malware/pe/MALW_Cythosia_pe.yar"
include "./malware/pe/MALW_Derkziel_pe.yar"
include "./malware/pe/MALW_Dexter_pe.yar"
include "./malware/pe/MALW_DiamondFox_pe.yar"
include "./malware/pe/MALW_Elex_pe.yar"
include "./malware/pe/MALW_Emotet_pe.yar"
include "./malware/pe/MALW_Empire_pe.yar"
include "./malware/pe/MALW_Enfal_pe.yar"
include "./malware/pe/MALW_Exploit_UAC_Elevators_pe.yar"
include "./malware/pe/MALW_Ezcob_pe.yar"
include "./malware/pe/MALW_F0xy_pe.yar"
include "./malware/pe/MALW_FakeM_pe.yar"
include "./malware/pe/MALW_FALLCHILL_pe.yar"
include "./malware/pe/MALW_Fareit_pe.yar"
include "./malware/pe/MALW_Favorite_pe.yar"
include "./malware/pe/MALW_Furtim_pe.yar"
include "./malware/pe/MALW_Genome_pe.yar"
include "./malware/pe/MALW_Glasses_pe.yar"
include "./malware/pe/MALW_Gozi_pe.yar"
include "./malware/pe/MALW_Grozlex_pe.yar"
include "./malware/pe/MALW_Hsdfihdf_banking_pe.yar"
include "./malware/pe/MALW_IcedID_pe.yar"
include "./malware/pe/MALW_Iexpl0ree_pe.yar"
include "./malware/pe/MALW_IMuler_pe.yar"
include "./malware/pe/MALW_Install11_pe.yar"
include "./malware/pe/MALW_Intel_Virtualization_pe.yar"
include "./malware/pe/MALW_Jolob_Backdoor_pe.yar"
include "./malware/pe/MALW_Kelihos_pe.yar"
include "./malware/pe/MALW_KeyBase_pe.yar"
include "./malware/pe/MALW_KINS_pe.yar"
include "./malware/pe/MALW_Korlia_pe.yar"
include "./malware/pe/MALW_Korplug_pe.yar"
include "./malware/pe/MALW_kpot_pe.yar"
include "./malware/pe/MALW_Kraken_pe.yar"
include "./malware/pe/MALW_Kwampirs_pe.yar"
include "./malware/pe/MALW_Lenovo_Superfish_pe.yar"
include "./malware/pe/MALW_LostDoor_pe.yar"
include "./malware/pe/MALW_LuckyCat_pe.yar"
include "./malware/pe/MALW_LURK0_pe.yar"
include "./malware/pe/MALW_MacControl_pe.yar"
include "./malware/pe/MALW_Madness_pe.yar"
include "./malware/pe/MALW_marap_pe.yar"
include "./malware/pe/MALW_Miancha_pe.yar"
include "./malware/pe/MALW_Miscelanea_Linux_pe.yar"
include "./malware/pe/MALW_Miscelanea_pe.yar"
include "./malware/pe/MALW_Monero_Miner_installer_pe.yar"
include "./malware/pe/MALW_MSILStealer_pe.yar"
include "./malware/pe/MALW_Naikon_pe.yar"
include "./malware/pe/MALW_Naspyupdate_pe.yar"
include "./malware/pe/MALW_NetTraveler_pe.yar"
include "./malware/pe/MALW_NionSpy_pe.yar"
include "./malware/pe/MALW_Notepad_pe.yar"
include "./malware/pe/MALW_NSFree_pe.yar"
include "./malware/pe/MALW_Odinaff_pe.yar"
include "./malware/pe/MALW_Olyx_pe.yar"
include "./malware/pe/MALW_PE_sections_pe.yar"
include "./malware/pe/MALW_PittyTiger_pe.yar"
include "./malware/pe/MALW_PolishBankRat_pe.yar"
include "./malware/pe/MALW_Ponmocup_pe.yar"
include "./malware/pe/MALW_Pony_pe.yar"
include "./malware/pe/MALW_Predator_pe.yar"
include "./malware/pe/MALW_PubSab_pe.yar"
include "./malware/pe/MALW_Pyinstaller_pe.yar"
include "./malware/pe/MALW_Quarian_pe.yar"
include "./malware/pe/MALW_Regsubdat_pe.yar"
include "./malware/pe/MALW_Rockloader_pe.yar"
include "./malware/pe/MALW_Rooter_pe.yar"
include "./malware/pe/MALW_Rovnix_pe.yar"
include "./malware/pe/MALW_Safenet_pe.yar"
include "./malware/pe/MALW_Sakurel_pe.yar"
include "./malware/pe/MALW_Sayad_pe.yar"
include "./malware/pe/MALW_Scarhikn_pe.yar"
include "./malware/pe/MALW_Shamoon_pe.yar"
include "./malware/pe/MALW_Shifu_pe.yar"
include "./malware/pe/MALW_shifu_shiz_pe.yar"
include "./malware/pe/MALW_sitrof_fortis_scar_pe.yar"
include "./malware/pe/MALW_Skeleton_pe.yar"
include "./malware/pe/MALW_Spora_pe.yar"
include "./malware/pe/MALW_Stealer_pe.yar"
include "./malware/pe/MALW_Surtr_pe.yar"
include "./malware/pe/MALW_T5000_pe.yar"
include "./malware/pe/MALW_Tedroo_pe.yar"
include "./malware/pe/MALW_TreasureHunt_pe.yar"
include "./malware/pe/MALW_TrickBot_pe.yar"
include "./malware/pe/MALW_TRITON_HATMAN_pe.yar"
include "./malware/pe/MALW_TRITON_ICS_FRAMEWORK_pe.yar"
include "./malware/pe/MALW_Upatre_pe.yar"
include "./malware/pe/MALW_Vidgrab_pe.yar"
include "./malware/pe/MALW_viotto_keylogger_pe.yar"
include "./malware/pe/MALW_Virut_FileInfector_UNK_VERSION_pe.yar"
include "./malware/pe/MALW_Volgmer_pe.yar"
include "./malware/pe/MALW_Wabot_pe.yar"
include "./malware/pe/MALW_Warp_pe.yar"
include "./malware/pe/MALW_Wimmie_pe.yar"
include "./malware/pe/MALW_xDedic_marketplace_pe.yar"
include "./malware/pe/MALW_Yayih_pe.yar"
include "./malware/pe/MALW_Yordanyan_ActiveAgent_pe.yar"
include "./malware/pe/MALW_Zegost_pe.yar"
include "./malware/pe/MALW_Zeus_pe.yar"
include "./malware/pe/POS_Bernhard_pe.yar"
include "./malware/pe/POS_Easterjack_pe.yar"
include "./malware/pe/POS_FastPOS_pe.yar"
include "./malware/pe/POS_LogPOS_pe.yar"
include "./malware/pe/POS_MalumPOS_pe.yar"
include "./malware/pe/POS_Mozart_pe.yar"
include "./malware/pe/POS_pe.yar"
include "./malware/pe/RANSOM_.CRYPTXXX_pe.yar"
include "./malware/pe/RANSOM_777_pe.yar"
include "./malware/pe/RANSOM_acroware_pe.yar"
include "./malware/pe/RANSOM_Alpha_pe.yar"
include "./malware/pe/RANSOM_BadRabbit_pe.yar"
include "./malware/pe/RANSOM_Cerber_pe.yar"
include "./malware/pe/RANSOM_Comodosec_pe.yar"
include "./malware/pe/RANSOM_Crypren_pe.yar"
include "./malware/pe/RANSOM_Cryptolocker_pe.yar"
include "./malware/pe/RANSOM_CryptoNar_pe.yar"
include "./malware/pe/RANSOM_DMALocker_pe.yar"
include "./malware/pe/RANSOM_DoublePulsar_Petya_pe.yar"
include "./malware/pe/RANSOM_GoldenEye_pe.yar"
include "./malware/pe/RANSOM_GPGQwerty_pe.yar"
include "./malware/pe/RANSOM_locdoor_pe.yar"
include "./malware/pe/RANSOM_Locky_pe.yar"
include "./malware/pe/RANSOM_Maze_pe.yar"
include "./malware/pe/RANSOM_MS17-010_Wannacrypt_pe.yar"
include "./malware/pe/RANSOM_PetrWrap_pe.yar"
include "./malware/pe/RANSOM_Petya_MS17_010_pe.yar"
include "./malware/pe/RANSOM_Petya_pe.yar"
include "./malware/pe/RANSOM_Pico_pe.yar"
include "./malware/pe/RANSOM_SamSam_pe.yar"
include "./malware/pe/RANSOM_Satana_pe.yar"
include "./malware/pe/RANSOM_screenlocker_5h311_1nj3c706_pe.yar"
include "./malware/pe/RANSOM_Shiva_pe.yar"
include "./malware/pe/RANSOM_shrug2_pe.yar"
include "./malware/pe/RANSOM_Sigma_pe.yar"
include "./malware/pe/RANSOM_Snake_pe.yar"
include "./malware/pe/RANSOM_Stampado_pe.yar"
include "./malware/pe/RANSOM_termite_pe.yar"
include "./malware/pe/RANSOM_TeslaCrypt_pe.yar"
include "./malware/pe/RANSOM_Tox_pe.yar"
include "./malware/pe/RAT_Asyncrat_pe.yar"
include "./malware/pe/RAT_BlackShades_pe.yar"
include "./malware/pe/RAT_Bozok_pe.yar"
include "./malware/pe/RAT_CyberGate_pe.yar"
include "./malware/pe/RAT_DarkComet_pe.yar"
include "./malware/pe/RAT_FlyingKitten_pe.yar"
include "./malware/pe/RAT_Gh0st_pe.yar"
include "./malware/pe/RAT_Gholee_pe.yar"
include "./malware/pe/RAT_Glass_pe.yar"
include "./malware/pe/RAT_Havex_pe.yar"
include "./malware/pe/RAT_Hizor_pe.yar"
include "./malware/pe/RAT_Indetectables_pe.yar"
include "./malware/pe/RAT_Inocnation_pe.yar"
include "./malware/pe/RAT_Nanocore_pe.yar"
include "./malware/pe/RAT_NetwiredRC_pe.yar"
include "./malware/pe/RAT_Njrat_pe.yar"
include "./malware/pe/RAT_Orcus_pe.yar"
include "./malware/pe/RAT_PlugX_pe.yar"
include "./malware/pe/RAT_PoisonIvy_pe.yar"
include "./malware/pe/RAT_Ratdecoders_pe.yar"
include "./malware/pe/RAT_Sakula_pe.yar"
include "./malware/pe/RAT_ShadowTech_pe.yar"
include "./malware/pe/RAT_Terminator_pe.yar"
include "./malware/pe/RAT_xRAT20_pe.yar"
include "./malware/pe/RAT_xRAT_pe.yar"
include "./malware/pe/RAT_Xtreme_pe.yar"
include "./malware/pe/RAT_ZoxPNG_pe.yar"
include "./malware/pe/TOOLKIT_Chinese_Hacktools_pe.yar"
include "./malware/pe/TOOLKIT_Dubrute_pe.yar"
include "./malware/pe/TOOLKIT_FinFisher__pe.yar"
include "./malware/pe/TOOLKIT_Gen_powerkatz_pe.yar"
include "./malware/pe/TOOLKIT_PassTheHash_pe.yar"
include "./malware/pe/TOOLKIT_Powerstager_pe.yar"
include "./malware/pe/TOOLKIT_Pwdump_pe.yar"
include "./malware/pe/TOOLKIT_THOR_HackTools_pe.yar"
include "./malware/pe/TOOLKIT_Wineggdrop_pe.yar"
include "./packers/pe/packer_compiler_signatures_pe.yar"
include "./packers/pe/packer_pe.yar"
include "./packers/pe/peid_pe.yar"
include "./webshells/pe/WShell_THOR_Webshells_pe.yar"
