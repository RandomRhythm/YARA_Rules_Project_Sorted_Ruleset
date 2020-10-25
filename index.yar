/*
Generated by YARA_Rules_Util
On 2020-10-23
*/
include "./cve_rules/Linux/CVE-2016-5195.yar"
include "./cve_rules/ace/CVE-2018-20250_ace.yar"
include "./cve_rules/jar/CVE-2010-0887_jar.yar"
include "./cve_rules/jar/CVE-2013-0422_jar.yar"
include "./cve_rules/office/CVE-2012-0158.yar"
include "./cve_rules/office/CVE-2017-11882.yar"
include "./cve_rules/pe/CVE-2010-0805_pe.yar"
include "./cve_rules/pe/CVE-2015-1701_pe.yar"
include "./cve_rules/pe/CVE-2015-2426_pe.yar"
include "./cve_rules/pe/CVE-2015-2545_pe.yar"
include "./cve_rules/swf/CVE-2010-1297_swf.yar"
include "./cve_rules/swf/CVE-2015-5119_swf.yar"
include "./cve_rules/swf/CVE-2018-4878_swf.yar"
include "./cve_rules/xap/CVE-2013-0074_xap.yar"
include "./email/zip/email_cryptowall_zip.yar"
include "./exploit_kits/html/EK_Angler_html.yar"
include "./exploit_kits/html/EK_Blackhole_html.yar"
include "./exploit_kits/html/EK_Eleonore_html.yar"
include "./exploit_kits/html/EK_Fragus_html.yar"
include "./exploit_kits/html/EK_Phoenix_html.yar"
include "./exploit_kits/html/EK_ZeroAcces_html.yar"
include "./exploit_kits/html/EK_Zerox88_html.yar"
include "./exploit_kits/html/EK_Zeus_html.yar"
include "./exploit_kits/jar/EK_Angler_jar.yar"
include "./exploit_kits/jar/EK_Blackhole_jar.yar"
include "./exploit_kits/jar/EK_BleedingLife_jar.yar"
include "./exploit_kits/jar/EK_Crimepack_jar.yar"
include "./exploit_kits/jar/EK_Eleonore_jar.yar"
include "./exploit_kits/jar/EK_Phoenix_jar.yar"
include "./exploit_kits/jar/EK_Sakura_jar.yar"
include "./exploit_kits/pdf/EK_Blackhole_pdf.yar"
include "./exploit_kits/pdf/EK_Phoenix_pdf.yar"
include "./exploit_kits/swf/EK_Angler_swf.yar"
include "./exploit_kits/swf/EK_BleedingLife_swf.yar"
include "./maldocs/doc/Maldoc_APT10_MenuPass_doc.yar"
include "./maldocs/hta/Maldoc_CVE_2017_8759_hta.yar"
include "./maldocs/multi/Maldoc_APT19_CVE-2017-0199.yar"
include "./maldocs/multi/Maldoc_APT_OLE_JSRat.yar"
include "./maldocs/multi/Maldoc_Contains_VBE_File.yar"
include "./maldocs/multi/Maldoc_CVE_2017_11882.yar"
include "./maldocs/multi/Maldoc_CVE_2017_8759.yar"
include "./maldocs/multi/Maldoc_DDE.yar"
include "./maldocs/multi/Maldoc_Dridex.yar"
include "./maldocs/multi/Maldoc_hancitor_dropper.yar"
include "./maldocs/multi/Maldoc_Hidden_PE_file.yar"
include "./maldocs/multi/Maldoc_MIME_ActiveMime_b64.yar"
include "./maldocs/multi/Maldoc_PowerPointMouse.yar"
include "./maldocs/multi/maldoc_somerules.yar"
include "./maldocs/multi/Maldoc_Suspicious_OLE_target.yar"
include "./maldocs/multi/Maldoc_UserForm.yar"
include "./maldocs/multi/Maldoc_VBA_macro_code.yar"
include "./maldocs/multi/Maldoc_Word_2007_XML_Flat_OPC.yar"
include "./maldocs/pdf/Maldoc_PDF_pdf.yar"
include "./maldocs/pe/Maldoc_Dridex_pe.yar"
include "./maldocs/ppt/Maldoc_PowerPointMouse_ppt.yar"
include "./maldocs/rtf/Maldoc_APT19_CVE-2017-0199_rtf.yar"
include "./maldocs/rtf/Maldoc_CVE-2017-0199_rtf.yar"
include "./maldocs/rtf/Maldoc_CVE_2017_8759_rtf.yar"
include "./maldocs/rtf/Maldoc_malrtf_ole2link_rtf.yar"
include "./maldocs/rtf/maldoc_somerules_rtf.yar"
include "./malware/Doc/APT_Poseidon_Group_doc_Doc.yar"
include "./malware/Doc/MALW_Miscelanea_doc.yar"
include "./malware/Doc/RAT_PoetRATDoc.yar"
include "./malware/Operation_Blockbuster/cert_wiper.yar"
include "./malware/Operation_Blockbuster/IndiaAlfa.yar"
include "./malware/Operation_Blockbuster/IndiaCharlie.yar"
include "./malware/Operation_Blockbuster/PapaAlfa.yar"
include "./malware/Operation_Blockbuster/suicidescripts.yar"
include "./malware/Operation_Blockbuster/TangoAlfa.yar"
include "./malware/Operation_Blockbuster/UniformJuliett.yar"
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
include "./malware/asp/APT_APT1_asp.yar"
include "./malware/asp/TOOLKIT_THOR_HackTools_asp.yar"
include "./malware/aspx/APT_Irontiger_aspx.yar"
include "./malware/bat/APT_EQUATIONGRP_bat.yar"
include "./malware/bat/APT_Sofacy_Bundestag_bat.yar"
include "./malware/bat/TOOLKIT_THOR_HackTools_bat.yar"
include "./malware/com/TOOLKIT_THOR_HackTools_com.yar"
include "./malware/dosZMXP/RANSOM_jeff_dev.yar"
include "./malware/elf/000_common_rules__elf.yar"
include "./malware/elf/000_common_rules_elf.yar"
include "./malware/elf/APT_Derusbi_elf.yar"
include "./malware/elf/APT_Derusbi_pe.yar"
include "./malware/elf/APT_EnergeticBear_backdoored_ssh_elf.yar"
include "./malware/elf/APT_eqgrp_apr17_elf.yar"
include "./malware/elf/APT_EQUATIONGRP_elf.yar"
include "./malware/elf/APT_Sofacy_Fysbis_elf.yar"
include "./malware/elf/APT_Windigo_Onimiki_elf.yar"
include "./malware/elf/MALW_Chicken_elf.yar"
include "./malware/elf/MALW_DDoSTf_elf.yar"
include "./malware/elf/MALW_Elknot_elf.yar"
include "./malware/elf/MALW_Gafgyt_elf.yar"
include "./malware/elf/MALW_Hajime_elf.yar"
include "./malware/elf/MALW_Httpsd_ELF_elf.yar"
include "./malware/elf/MALW_IotReaper_elf.yar"
include "./malware/elf/MALW_LinuxBew_elf.yar"
include "./malware/elf/MALW_LinuxHelios_elf.yar"
include "./malware/elf/MALW_LinuxMoose_elf.yar"
include "./malware/elf/MALW_LuaBot_elf.yar"
include "./malware/elf/MALW_Mirai_elf.yar"
include "./malware/elf/MALW_Mirai_Okiru_ELF_elf.yar"
include "./malware/elf/MALW_Mirai_Satori_ELF_elf.yar"
include "./malware/elf/MALW_Miscelanea_Linux_elf.yar"
include "./malware/elf/MALW_Rebirth_Vulcan_ELF_elf.yar"
include "./malware/elf/MALW_Torte_ELF_elf.yar"
include "./malware/elf/MALW_Trumpbot_elf.yar"
include "./malware/elf/MALW_XHide_elf.yar"
include "./malware/elf/MALW_XOR_DDos_elf.yar"
include "./malware/elf/RANSOM_Erebus_elf.yar"
include "./malware/elf/TOOLKIT_Mandibule_elf.yar"
include "./malware/elf/TOOLKIT_THOR_HackTools_elf.yar"
include "./malware/eml/MALW_Mailers_eml.yar"
include "./malware/evt/MALW_Andromeda_evt.yar"
include "./malware/evt/MALW_Kovter_evt.yar"
include "./malware/evt/MALW_Lateral_Movement_evt.yar"
include "./malware/evt/POS_BruteforcingBot_evt.yar"
include "./malware/evt/RAT_DarkComet_evt.yar"
include "./malware/evt/RAT_Xtreme_evt.yar"
include "./malware/ini/TOOLKIT_THOR_HackTools_ini.yar"
include "./malware/jar/APT_eqgrp_apr17_jar.yar"
include "./malware/jar/MALW_adwind_RAT_jar.yar"
include "./malware/jar/RAT_Adwind_jar.yar"
include "./malware/jar/RAT_Adzok_jar.yar"
include "./malware/jar/RAT_Crimson_jar.yar"
include "./malware/jar/RAT_CrossRAT_jar.yar"
include "./malware/jar/RAT_Ratdecoders_jar.yar"
include "./malware/js/APT_TradeSecret_js.yar"
include "./malware/jsp/APT_Irontiger_jsp.yar"
include "./malware/jsp/TOOLKIT_THOR_HackTools_jsp.yar"
include "./malware/lnk/APT_Stuxnet_lnk.yar"
include "./malware/lnk/MALW_Miscelanea_lnk.yar"
include "./malware/lsp/apt_equationgrp_lsp.yar"
include "./malware/lua/APT_Sauron_extras_lua.yar"
include "./malware/mbr/APT_fancybear_downdelph_mbr.yar"
include "./malware/mem/APT_C16_pe.yar"
include "./malware/mem/APT_RedLeaves_mem.yar"
include "./malware/mem/EXPERIMENTAL_Beef_mem.yar"
include "./malware/mem/MalConfScan_mem.yar"
include "./malware/mem/MALW_AgentTesla_SMTP_mem.yar"
include "./malware/mem/MALW_AlMashreq_mem.yar"
include "./malware/mem/MALW_Citadel_mem.yar"
include "./malware/mem/MALW_hancitor_mem.yar"
include "./malware/mem/MALW_MedusaHTTP_2019_mem.yar"
include "./malware/mem/MALW_MiniAsp3_mem.yar"
include "./malware/mem/MALW_Miscelanea_mem.yar"
include "./malware/mem/MALW_Sendsafe_mem.yar"
include "./malware/mem/MALW_Tinba_mem.yar"
include "./malware/mem/MALW_Urausy_mem.yar"
include "./malware/mem/RANSOM_MS17-010_Wannacrypt_mem.yar"
include "./malware/mem/RAT_BlackShades_mem.yar"
include "./malware/mem/RAT_Bolonyokte_mem.yar"
include "./malware/mem/RAT_Cerberus_mem.yar"
include "./malware/mem/RAT_DarkComet_mem.yar"
include "./malware/mem/RAT_jRAT_mem.yar"
include "./malware/mem/RAT_Meterpreter_Reverse_Tcp_mem.yar"
include "./malware/mem/RAT_Terminator_mem.yar"
include "./malware/mem/RAT_Xtreme_mem.yar"
include "./malware/mem/TOOLKIT_THOR_HackTools_mem.yar"
include "./malware/mem/TOOLKIT_THOR_HackTools_memory_mem.yar"
include "./malware/multi/APT_HiddenCobra_multi.yar"
include "./malware/multi/APT_MoonlightMaze.yar"
include "./malware/multi/APT_Sauron_extras.yar"
include "./malware/multi/MALW_Cloaking.yar"
include "./malware/multi/MALW_Eicar.yar"
include "./malware/multi/MALW_Miscelanea_multi.yar"
include "./malware/multi/MALW_Retefe.yar"
include "./malware/multi/MALW_TinyShell_Backdoor_gen.yar"
include "./malware/multi/MALW_XMRIG_Miner.yar"
include "./malware/multi/TOOLKIT_exe2hex_payload.yar"
include "./malware/osx/MALW_OSX_Leverage_osx.yar"
include "./malware/pdf/APT_NGO_pdf.yar"
include "./malware/pdf/APT_Waterbug_pdf.yar"
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
include "./malware/php/APT_APT29_Grizzly_Steppe_php.yar"
include "./malware/php/MALW_Magento_backend_php.yar"
include "./malware/php/MALW_Magento_frontend_php.yar"
include "./malware/php/MALW_Magento_suspicious_php.yar"
include "./malware/php/RAT_Havex_php.yar"
include "./malware/pl/APT_eqgrp_apr17_pl.yar"
include "./malware/pl/APT_EQUATIONGRP_pl.yar"
include "./malware/pl/TOOLKIT_THOR_HackTools_pl.yar"
include "./malware/ps1/APT_Cobalt_ps1.yar"
include "./malware/ps1/APT_Oilrig_ps1.yar"
include "./malware/ps1/GEN_PowerShell_ps1.yar"
include "./malware/ps1/MALW_Empire_ps1.yar"
include "./malware/ps1/MALW_Miscelanea_ps1.yar"
include "./malware/ps1/TOOLKIT_THOR_HackTools_ps1.yar"
include "./malware/py/APT_eqgrp_apr17_py.yar"
include "./malware/py/APT_EQUATIONGRP_py.yar"
include "./malware/py/MALW_BackdoorSSH_py.yar"
include "./malware/py/MALW_PyPI_py.yar"
include "./malware/py/RAT_PoetRATPython_py.yar"
include "./malware/rar/MALW_Rockloader_rar.yar"
include "./malware/rar/TOOLKIT_THOR_HackTools_rar.yar"
include "./malware/reg/TOOLKIT_THOR_HackTools_reg.yar"
include "./malware/rtf/APT_Mongall_rtf.yar"
include "./malware/rtf/APT_Poseidon_Group_rtf.yar"
include "./malware/sh/APT_eqgrp_apr17_sh.yar"
include "./malware/sh/APT_EQUATIONGRP_sh.yar"
include "./malware/sh/TOOLKIT_THOR_HackTools_sh.yar"
include "./malware/shim/RAT_Shim_shim.yar"
include "./malware/sqlite/MALW_Sqlite.yar"
include "./malware/txt/APT_Oilrig_txt.yar"
include "./malware/txt/TOOLKIT_THOR_HackTools_txt.yar"
include "./malware/unknown/MALW_DirtJumper.yar"
include "./malware/vbs/APT_Blackenergy_vbs.yar"
include "./malware/vbs/APT_Minidionis_vbs.yar"
include "./malware/vbs/APT_Oilrig_vbs.yar"
include "./malware/vbs/MALW_BlackWorm_vbs.yar"
include "./malware/vbs/MALW_FUDCrypt_vbs.yar"
include "./malware/vbs/TOOLKIT_THOR_HackTools_vbs.yar"
include "./malware/xls/APT_Oilrig_xls.yar"
include "./malware/xls/RANSOM_GoldenEye_xls.yar"
include "./malware/xml/APT_FiveEyes_xml.yar"
include "./malware/zip/APT_Minidionis_zip.yar"
include "./packers/js/Javascript_exploit_and_obfuscation_js.yar"
include "./packers/js/JJencode_js.yar"
include "./packers/pe/packer_compiler_signatures_pe.yar"
include "./packers/pe/packer_pe.yar"
include "./packers/pe/peid_pe.yar"
include "./utils/virustotal.yar"
include "./utils/unknown/base64.yar"
include "./webshells/asp/WShell_APT_Laudanum_asp.yar"
include "./webshells/asp/WShell_THOR_Webshells_asp.yar"
include "./webshells/aspx/WShell_APT_Laudanum_aspx.yar"
include "./webshells/aspx/WShell_ASPXSpy_aspx.yar"
include "./webshells/aspx/WShell_THOR_Webshells_aspx.yar"
include "./webshells/cfm/WShell_APT_Laudanum_cfm.yar"
include "./webshells/cgi/WShell_THOR_Webshells_cgi.yar"
include "./webshells/cmd/WShell_THOR_Webshells_cmd.yar"
include "./webshells/gif/WShell_THOR_Webshells_gif.yar"
include "./webshells/html/WShell_THOR_Webshells_html.yar"
include "./webshells/js/WShell_THOR_Webshells_js.yar"
include "./webshells/jsp/WShell_APT_Laudanum_jsp.yar"
include "./webshells/jsp/WShell_THOR_Webshells_jsp.yar"
include "./webshells/multi/WShell_PHP_in_images.yar"
include "./webshells/pe/WShell_THOR_Webshells_pe.yar"
include "./webshells/php/WShell_APT_Laudanum_php.yar"
include "./webshells/php/Wshell_ChineseSpam_php.yar"
include "./webshells/php/wshell_drupalgeddon2_icos_php.yar"
include "./webshells/php/Wshell_fire2013_php.yar"
include "./webshells/php/WShell_PHP_Anuna_php.yar"
include "./webshells/php/WShell_THOR_Webshells_php.yar"
include "./webshells/pl/WShell_THOR_Webshells_pl.yar"
include "./webshells/py/WShell_THOR_Webshells_py.yar"
include "./webshells/unknown/WShell_THOR_Webshells.yar"
include "./webshells/war/WShell_APT_Laudanum_war.yar"
include "./webshells/xml/WShell_APT_Laudanum_xml.yar"
