package io.security.corespringsecurity.dto.admin;


import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.dto.ResourcesDto;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.service.MethodSecurityService;
import io.security.corespringsecurity.service.ResourcesService;
import io.security.corespringsecurity.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Controller
@RequiredArgsConstructor
public class ResourcesController {

    private final ResourcesService resourcesService;
    private final RoleRepository roleRepository;
    private final RoleService roleService;

    private final MethodSecurityService methodSecurityService;
    private final UrlFilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource;

    @GetMapping(value="/admin/resources")
    public String getResources(Model model) throws Exception {

        List<Resources> resources = resourcesService.getResources();
        model.addAttribute("resources", resources);

        return "admin/resource/list";
    }


    //권한정보 추가시 실시간 반영시키기기
    @PostMapping("/admin/resources")
   public String createResources(ResourcesDto resourcesDto) throws Exception {

        ModelMapper modelMapper = new ModelMapper();
        Role role = roleRepository.findByRoleName(resourcesDto.getRoleName());
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        Resources resources = modelMapper.map(resourcesDto, Resources.class);
        resources.setRoleSet(roles);

        resourcesService.createResources(resources);

        if ("url".equals(resourcesDto.getResourceType())) {
            filterInvocationSecurityMetadataSource.reload();
        } else {
            methodSecurityService.addMethodSecured(resourcesDto.getResourceName() , resourcesDto.getRoleName());
        }
       return "redirect:/admin/resources";
    }


    @GetMapping(value="/admin/resources/register")
    public String viewRoles(Model model) throws Exception {

        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);
        Resources resources = new Resources();
        model.addAttribute("resources", resources);

        return "admin/resource/detail";
    }

    @GetMapping(value="/admin/resources/{id}")
    public String getResources(@PathVariable String id, Model model) throws Exception {

        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);
        Resources resources = resourcesService.getResources(Long.valueOf(id));
        model.addAttribute("resources", resources);

        return "admin/resource/detail";
    }


    //권한정보 삭제시 실시간 반영시키기기
   @PostMapping("/admin/resources/delete/{id}")
    public String removeResources(@PathVariable String id , Model model) throws Exception {

        Resources resources = resourcesService.getResources(Long.valueOf(id));
        resourcesService.deleteResources(Long.valueOf(id));

       if ("url".equals(resources.getResourceType())) {
           filterInvocationSecurityMetadataSource.reload();
       } else {
           methodSecurityService.removeMethodSecured(resources.getResourceName());
       }
        return "redirect:/admin/resources";
    }

}